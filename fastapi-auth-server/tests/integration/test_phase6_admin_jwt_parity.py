from __future__ import annotations

import json
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import jwt
import pytest

from wiseacct_sso.application.admin import Phase6AdminService
from wiseacct_sso.config import Settings
from wiseacct_sso.domain.tokens import TokenValidationError
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.infrastructure.security import JwtTokenCodec
from wiseacct_sso.persistence.database import Database

ROOT = Path(__file__).parents[2]
AUTH_SERVER = ROOT.parent / "auth-server"
NODE_BRIDGE = ROOT / "tests" / "helpers" / "node_jwt_bridge.cjs"
NODE_AVAILABLE = (
    shutil.which("node") is not None and (AUTH_SERVER / "node_modules/jsonwebtoken").exists()
)

pytestmark = [
    pytest.mark.skipif(not NODE_AVAILABLE, reason="Node jsonwebtoken fixture is unavailable"),
]


def _node(input_payload: dict[str, object]) -> dict[str, object]:
    completed = subprocess.run(  # noqa: S603
        ["node", str(NODE_BRIDGE)],  # noqa: S607
        cwd=AUTH_SERVER,
        input=json.dumps(input_payload),
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0
    return cast(dict[str, object], json.loads(completed.stdout))


def _node_token(settings: Settings, payload: dict[str, object]) -> str:
    response = _node(
        {
            "operation": "sign-access",
            "payload": payload,
            "privateKey": settings.jwt_access_private_key,
            "keyId": settings.jwt_access_key_id,
        }
    )
    assert response["ok"] is True
    return cast(str, response["result"])


def _node_verdict(settings: Settings, token: str) -> dict[str, object]:
    return _node(
        {
            "operation": "verify-admin-access",
            "token": token,
            "publicJwk": settings.jwt_access_public_jwk.model_dump(),
            "issuer": settings.jwt_issuer,
            "audience": settings.jwt_audience,
        }
    )


def _payload(settings: Settings, **overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "sub": "admin-user",
        "type": "access",
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
    }
    payload.update(overrides)
    return payload


@pytest.mark.parametrize(
    ("overrides", "expected_subject"),
    [
        ({}, "admin-user"),
        ({"sub": ""}, ""),
        (
            {
                "email": 42,
                "email_verified": "not-a-boolean",
                "roles": "not-a-list",
            },
            "admin-user",
        ),
    ],
)
def test_admin_verifier_accepts_same_minimal_node_payloads_as_express(
    synthetic_settings: Settings,
    overrides: dict[str, object],
    expected_subject: str,
) -> None:
    token = _node_token(synthetic_settings, _payload(synthetic_settings, **overrides))

    assert _node_verdict(synthetic_settings, token) == {
        "ok": True,
        "result": {"classification": "accepted", "sub": expected_subject},
    }
    assert (
        JwtTokenCodec.from_settings(synthetic_settings).verify_admin_access_subject(token)
        == expected_subject
    )


@pytest.mark.anyio
async def test_admin_application_rejects_node_signed_empty_subject_before_database(
    synthetic_settings: Settings,
) -> None:
    token = _node_token(synthetic_settings, _payload(synthetic_settings, sub=""))

    def unexpected_database() -> Database:
        pytest.fail("empty subject must not reach the database")

    service = Phase6AdminService(
        database=unexpected_database,
        tokens=JwtTokenCodec.from_settings(synthetic_settings),
    )
    with pytest.raises(DomainError) as caught:
        await service.authenticate_admin(token, route="/admin/users", method="GET")

    assert (caught.value.status_code, caught.value.code, caught.value.message) == (
        401,
        "UNAUTHORIZED",
        "Authentication is required",
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"sub": None},
        {"sub": 7},
        {"type": "refresh"},
        {"type": None},
    ],
)
def test_admin_verifier_maps_same_node_payload_shape_failures_to_invalid_token(
    synthetic_settings: Settings,
    overrides: dict[str, object],
) -> None:
    token = _node_token(synthetic_settings, _payload(synthetic_settings, **overrides))

    assert _node_verdict(synthetic_settings, token) == {
        "ok": True,
        "result": {"classification": "invalid-shape"},
    }
    with pytest.raises(TokenValidationError):
        JwtTokenCodec.from_settings(synthetic_settings).verify_admin_access_subject(token)


def test_admin_verifier_maps_missing_subject_to_invalid_token(
    synthetic_settings: Settings,
) -> None:
    payload = _payload(synthetic_settings)
    del payload["sub"]
    token = _node_token(synthetic_settings, payload)

    assert _node_verdict(synthetic_settings, token) == {
        "ok": True,
        "result": {"classification": "invalid-shape"},
    }
    with pytest.raises(TokenValidationError):
        JwtTokenCodec.from_settings(synthetic_settings).verify_admin_access_subject(token)


@pytest.mark.parametrize(
    ("overrides", "node_error", "python_error"),
    [
        (
            {"exp": int((datetime.now(UTC) - timedelta(minutes=1)).timestamp())},
            "TokenExpiredError",
            jwt.ExpiredSignatureError,
        ),
        ({"iss": "https://wrong.invalid"}, "JsonWebTokenError", jwt.InvalidIssuerError),
        ({"aud": "wrong-audience"}, "JsonWebTokenError", jwt.InvalidAudienceError),
    ],
)
def test_admin_verifier_preserves_same_jwt_verification_failures_for_generic_500(
    synthetic_settings: Settings,
    overrides: dict[str, object],
    node_error: str,
    python_error: type[jwt.PyJWTError],
) -> None:
    token = _node_token(synthetic_settings, _payload(synthetic_settings, **overrides))

    assert _node_verdict(synthetic_settings, token) == {"ok": False, "error": node_error}
    with pytest.raises(python_error):
        JwtTokenCodec.from_settings(synthetic_settings).verify_admin_access_subject(token)


def test_admin_verifier_rejects_tampered_node_token_as_verification_error(
    synthetic_settings: Settings,
) -> None:
    token = _node_token(synthetic_settings, _payload(synthetic_settings))
    header, payload, signature = token.split(".")
    replacement = "A" if signature[0] != "A" else "B"
    tampered = ".".join((header, payload, replacement + signature[1:]))

    assert _node_verdict(synthetic_settings, tampered) == {
        "ok": False,
        "error": "JsonWebTokenError",
    }
    with pytest.raises(jwt.InvalidSignatureError):
        JwtTokenCodec.from_settings(synthetic_settings).verify_admin_access_subject(tampered)


def test_admin_verifier_preserves_wrong_algorithm_as_verification_error(
    synthetic_settings: Settings,
) -> None:
    response = _node(
        {
            "operation": "sign-access-hs256",
            "payload": _payload(synthetic_settings),
            "secret": synthetic_settings.jwt_refresh_secret,
        }
    )
    assert response["ok"] is True
    token = cast(str, response["result"])

    assert _node_verdict(synthetic_settings, token) == {
        "ok": False,
        "error": "JsonWebTokenError",
    }
    with pytest.raises(jwt.InvalidAlgorithmError):
        JwtTokenCodec.from_settings(synthetic_settings).verify_admin_access_subject(token)
