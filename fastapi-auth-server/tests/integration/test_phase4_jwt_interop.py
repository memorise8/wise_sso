from __future__ import annotations

import json
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from wiseacct_sso.config import Settings
from wiseacct_sso.domain.tokens import AccessTokenIdentity, RoleClaim, TokenValidationError
from wiseacct_sso.infrastructure.security import JwtTokenCodec

ROOT = Path(__file__).parents[2]
AUTH_SERVER = ROOT.parent / "auth-server"
NODE_BRIDGE = ROOT / "tests" / "helpers" / "node_jwt_bridge.cjs"
NODE_AVAILABLE = (
    shutil.which("node") is not None and (AUTH_SERVER / "node_modules/jsonwebtoken").exists()
)

pytestmark = [
    pytest.mark.skipif(not NODE_AVAILABLE, reason="Node jsonwebtoken fixture is unavailable"),
    pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning"),
]


def _codec(settings: Settings) -> JwtTokenCodec:
    return JwtTokenCodec.from_settings(settings)


def _identity() -> AccessTokenIdentity:
    return AccessTokenIdentity(
        user_id="phase4-user",
        email="interop@example.invalid",
        name="Interop User",
        email_verified=True,
        roles=(RoleClaim(service_key="temis", name="user"),),
    )


def _access_payload(
    settings: Settings,
    *,
    claim_kind: str = "access",
    audience: str = "temis",
) -> dict[str, object]:
    issued_at = datetime.now(UTC).replace(microsecond=0)
    return {
        "sub": "phase4-user",
        "email": "interop@example.invalid",
        "name": "Interop User",
        "email_verified": True,
        "type": claim_kind,
        "roles": [{"serviceKey": "temis", "name": "user"}],
        "iat": int(issued_at.timestamp()),
        "exp": int((issued_at + timedelta(minutes=5)).timestamp()),
        "iss": settings.jwt_issuer,
        "aud": audience,
    }


def _refresh_payload(*, claim_kind: str = "refresh", audience: str = "temis") -> dict[str, object]:
    issued_at = datetime.now(UTC).replace(microsecond=0)
    return {
        "sub": "phase4-user",
        "type": claim_kind,
        "tokenId": "a" * 64,
        "audience": audience,
        "iat": int(issued_at.timestamp()),
        "exp": int((issued_at + timedelta(days=1)).timestamp()),
    }


def _node(input_payload: dict[str, object]) -> object:
    __tracebackhide__ = True
    completed = subprocess.run(  # noqa: S603
        ["node", str(NODE_BRIDGE)],  # noqa: S607
        cwd=AUTH_SERVER,
        input=json.dumps(input_payload),
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if completed.returncode != 0:
        pytest.fail(f"Node JWT bridge exited with status {completed.returncode}")
    try:
        response = cast(dict[str, object], json.loads(completed.stdout))
    except json.JSONDecodeError:
        pytest.fail("Node JWT bridge returned malformed output")
    if response.get("ok") is not True:
        pytest.fail(f"Node JWT bridge rejected the operation: {response.get('error', 'Error')}")
    return response.get("result")


def _node_token(input_payload: dict[str, object]) -> str:
    __tracebackhide__ = True
    result = _node(input_payload)
    if not isinstance(result, str):
        pytest.fail("Node JWT bridge did not return a token")
    return result


def _node_access_token(settings: Settings) -> str:
    __tracebackhide__ = True
    return _node_token(
        {
            "operation": "sign-access",
            "payload": _access_payload(settings),
            "privateKey": settings.jwt_access_private_key,
            "keyId": settings.jwt_access_key_id,
        }
    )


def test_python_accepts_node_jsonwebtoken_rs256_access_token(synthetic_settings: Settings) -> None:
    token = _node_access_token(synthetic_settings)

    claims = _codec(synthetic_settings).verify_access_token(token, audience="temis")

    assert claims.identity == _identity()


def test_node_jsonwebtoken_accepts_python_rs256_access_token(synthetic_settings: Settings) -> None:
    token = _codec(synthetic_settings).issue_access_token(_identity(), audience="temis")

    result = _node(
        {
            "operation": "verify-access",
            "token": token,
            "publicJwk": synthetic_settings.jwt_access_public_jwk.model_dump(),
            "issuer": synthetic_settings.jwt_issuer,
            "audience": "temis",
        }
    )

    assert result == {"sub": "phase4-user", "type": "access"}


def test_python_accepts_node_jsonwebtoken_hs256_refresh_token(
    synthetic_settings: Settings,
) -> None:
    token = _node_token(
        {
            "operation": "sign-refresh",
            "payload": _refresh_payload(),
            "secret": synthetic_settings.jwt_refresh_secret,
        }
    )

    claims = _codec(synthetic_settings).verify_refresh_token(token, audience="temis")

    assert (claims.user_id, claims.token_id, claims.audience) == ("phase4-user", "a" * 64, "temis")


def test_node_jsonwebtoken_accepts_python_hs256_refresh_token(
    synthetic_settings: Settings,
) -> None:
    token = (
        _codec(synthetic_settings)
        .issue_refresh_token(user_id="phase4-user", audience="temis")
        .token
    )

    result = _node(
        {
            "operation": "verify-refresh",
            "token": token,
            "secret": synthetic_settings.jwt_refresh_secret,
            "audience": "temis",
        }
    )

    assert result == {"sub": "phase4-user", "type": "refresh", "audience": "temis"}


@pytest.mark.parametrize("origin", ["node", "python"])
def test_public_jwks_validates_access_token_from_each_runtime(
    synthetic_settings: Settings,
    origin: str,
) -> None:
    token = (
        _node_access_token(synthetic_settings)
        if origin == "node"
        else _codec(synthetic_settings).issue_access_token(_identity(), audience="temis")
    )

    result = _node(
        {
            "operation": "verify-jwks",
            "token": token,
            "publicJwk": synthetic_settings.jwt_access_public_jwk.model_dump(),
            "issuer": synthetic_settings.jwt_issuer,
            "audience": "temis",
        }
    )

    assert result == {"sub": "phase4-user"}


def test_python_rejects_node_access_token_with_hs256_algorithm(
    synthetic_settings: Settings,
) -> None:
    token = _node_token(
        {
            "operation": "sign-access-hs256",
            "payload": _access_payload(synthetic_settings),
            "secret": synthetic_settings.jwt_refresh_secret,
        }
    )

    with pytest.raises(TokenValidationError, match=r"^Invalid token$"):
        _codec(synthetic_settings).verify_access_token(token, audience="temis")


def test_python_rejects_node_access_token_with_refresh_type(
    synthetic_settings: Settings,
) -> None:
    token = _node_token(
        {
            "operation": "sign-access",
            "payload": _access_payload(synthetic_settings, claim_kind="refresh"),
            "privateKey": synthetic_settings.jwt_access_private_key,
            "keyId": synthetic_settings.jwt_access_key_id,
        }
    )

    with pytest.raises(TokenValidationError, match=r"^Invalid token$"):
        _codec(synthetic_settings).verify_access_token(token, audience="temis")


def test_python_rejects_node_access_token_with_wrong_audience(
    synthetic_settings: Settings,
) -> None:
    token = _node_token(
        {
            "operation": "sign-access",
            "payload": _access_payload(synthetic_settings, audience="other-service"),
            "privateKey": synthetic_settings.jwt_access_private_key,
            "keyId": synthetic_settings.jwt_access_key_id,
        }
    )

    with pytest.raises(TokenValidationError, match=r"^Invalid token$"):
        _codec(synthetic_settings).verify_access_token(token, audience="temis")


def test_python_rejects_node_refresh_token_with_hs384_algorithm(
    synthetic_settings: Settings,
) -> None:
    token = _node_token(
        {
            "operation": "sign-refresh",
            "payload": _refresh_payload(),
            "secret": synthetic_settings.jwt_refresh_secret,
            "algorithm": "HS384",
        }
    )

    with pytest.raises(TokenValidationError, match=r"^Invalid token$"):
        _codec(synthetic_settings).verify_refresh_token(token, audience="temis")


def test_python_rejects_node_refresh_token_with_access_type(
    synthetic_settings: Settings,
) -> None:
    token = _node_token(
        {
            "operation": "sign-refresh",
            "payload": _refresh_payload(claim_kind="access"),
            "secret": synthetic_settings.jwt_refresh_secret,
        }
    )

    with pytest.raises(TokenValidationError, match=r"^Invalid token$"):
        _codec(synthetic_settings).verify_refresh_token(token, audience="temis")


def test_python_rejects_node_refresh_token_with_wrong_audience(
    synthetic_settings: Settings,
) -> None:
    token = _node_token(
        {
            "operation": "sign-refresh",
            "payload": _refresh_payload(audience="other-service"),
            "secret": synthetic_settings.jwt_refresh_secret,
        }
    )

    with pytest.raises(TokenValidationError, match=r"^Invalid token$"):
        _codec(synthetic_settings).verify_refresh_token(token, audience="temis")


def test_public_jwk_contains_no_private_rsa_material(synthetic_settings: Settings) -> None:
    private_fields = {"d", "p", "q", "dp", "dq", "qi"}

    assert not (private_fields & synthetic_settings.jwt_access_public_jwk.model_dump().keys())
