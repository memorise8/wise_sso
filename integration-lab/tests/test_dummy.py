import base64
import hashlib
import importlib.util
import json
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

spec = importlib.util.spec_from_file_location(
    "dummy_app", Path(__file__).parents[1] / "app.py"
)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(PRIVATE.public_key()))
JWK["kid"] = "test-key"


def token(expected_nonce, **changes):
    claims = {
        "sub": "user-1",
        "iss": "https://localhost:4444",
        "aud": "lab-customer",
        "nonce": expected_nonce,
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
    }
    claims.update(changes)
    return jwt.encode(claims, PRIVATE, algorithm="RS256", headers={"kid": "test-key"})


@pytest.mark.parametrize(
    "claim,value",
    [
        ("iss", "https://wrong.invalid"),
        ("aud", "other-client"),
        ("nonce", "wrong"),
        ("exp", 1),
        ("sub", ""),
    ],
)
def test_id_token_rejects_invalid_claim(claim, value):
    config = module.Config("customer", "lab-customer", "secret")
    with pytest.raises((ValueError, jwt.PyJWTError)):
        module.verify_id_token(
            token("nonce", **{claim: value}), {"keys": [JWK]}, config, "nonce"
        )


def test_id_token_rejects_algorithm_confusion_and_unknown_key():
    config = module.Config("customer", "lab-customer", "secret")
    with pytest.raises(ValueError):
        module.verify_id_token(
            jwt.encode({"sub": "x"}, "a" * 32, algorithm="HS256"),
            {"keys": [JWK]},
            config,
            "nonce",
        )
    with pytest.raises(ValueError):
        module.verify_id_token(token("nonce"), {"keys": []}, config, "nonce")


def begin(client):
    result = client.get("/login", follow_redirects=False)
    assert result.status_code == 303
    params = parse_qs(urlsplit(result.headers["location"]).query)
    return params


@pytest.fixture
def rp():
    config = module.Config("customer", "lab-customer", "secret")
    calls = []
    nonce = [""]
    denied = [False]

    def handler(request):
        calls.append(request)
        if request.url.path == "/oauth2/token":
            return httpx.Response(
                200,
                json={
                    "id_token": token(nonce[0]),
                    "access_token": "opaque-private-token",
                },
            )
        if request.url.path == "/.well-known/jwks.json":
            return httpx.Response(200, json={"keys": [JWK]})
        if request.url.path == "/oauth2/userinfo":
            if denied[0]:
                return httpx.Response(401, json={"error": "invalid_token"})
            return httpx.Response(
                200,
                json={
                    "sub": "user-1",
                    "email": "user@lab.invalid",
                    "groups": ["lab-customer:user"],
                },
            )
        raise AssertionError(request.url)

    app = module.create_app(config, httpx.MockTransport(handler))
    with TestClient(app, base_url="https://localhost:4445") as client:
        yield app, client, calls, nonce, denied


def finish(client, params):
    return client.get(
        "/callback?" + urlencode({"code": "one-use-code", "state": params["state"][0]}),
        follow_redirects=False,
    )


def test_full_login_pkce_cookie_session_and_replay(rp):
    app, client, calls, nonce, denied = rp
    params = begin(client)
    nonce[0] = params["nonce"][0]
    result = finish(client, params)
    assert result.status_code == 303
    assert (
        "Secure" in result.headers["set-cookie"]
        and "HttpOnly" in result.headers["set-cookie"]
    )
    assert "one-use-code" not in result.headers["location"]
    request = next(r for r in calls if r.url.path == "/oauth2/token")
    assert (
        request.headers["authorization"]
        == "Basic " + base64.b64encode(b"lab-customer:secret").decode()
    )
    verifier = parse_qs(request.content.decode())["code_verifier"][0]
    assert params["code_challenge"] == [
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    ]
    home = client.get("/")
    assert "user@lab.invalid" in home.text and "lab-customer:user" in home.text
    assert "opaque-private-token" not in home.text
    assert home.headers["cache-control"] == "no-store"
    count = len(calls)
    assert finish(client, params).status_code == 400
    assert len(calls) == count
    denied[0] = True
    assert client.get("/").status_code == 401
    assert not app.state.sessions


def test_state_mismatch_and_other_browser_cannot_exchange(rp):
    app, client, calls, _nonce, _ = rp
    params = begin(client)
    assert client.get("/callback?code=x&state=wrong").status_code == 400
    assert not calls
    cookie = client.cookies.get("wise_lab_customer")
    client.cookies.clear()
    assert finish(client, params).status_code == 400
    assert not calls
    assert cookie in app.state.pending


def test_expired_flow_and_provider_denial(rp):
    app, client, calls, _nonce, _ = rp
    params = begin(client)
    flow = next(iter(app.state.pending.values()))
    flow.expires = 0
    assert finish(client, params).status_code == 400
    params = begin(client)
    result = client.get(
        "/callback?"
        + urlencode({"error": "access_denied", "state": params["state"][0]})
    )
    assert result.status_code == 403
    assert not calls and not app.state.sessions


def test_logout_csrf_and_session_deletion(rp):
    app, client, _calls, nonce, _ = rp
    params = begin(client)
    nonce[0] = params["nonce"][0]
    assert finish(client, params).status_code == 303
    assert client.post("/logout", data={"csrf": "wrong"}).status_code == 403
    assert len(app.state.sessions) == 1
    csrf = next(iter(app.state.sessions.values())).csrf
    assert (
        client.post("/logout", data={"csrf": csrf}, follow_redirects=False).status_code
        == 303
    )
    assert not app.state.sessions
    assert "wise-sso로 로그인" in client.get("/").text


def test_services_use_distinct_cookie_names():
    assert (
        module.Config("staff", "lab-staff", "s").cookie
        != module.Config("customer", "lab-customer", "s").cookie
    )


def test_proxy_keeps_upstream_referrer_policy_for_login_origin_check():
    config = (Path(__file__).parents[1] / "nginx.conf").read_text()
    assert not any(
        line.strip().startswith("add_header Referrer-Policy")
        for line in config.splitlines()
    )


@pytest.mark.parametrize(
    "params", [{"prompt": "login"}, {"prompt": "none"}, {"max_age": "0"}]
)
def test_login_passes_bounded_reauthentication_options(rp, params):
    client = rp[1]
    response = client.get("/login", params=params, follow_redirects=False)
    query = parse_qs(urlsplit(response.headers["location"]).query)
    for name, value in params.items():
        assert query[name] == [value]


@pytest.mark.parametrize(
    "query",
    [
        "prompt=bad",
        "prompt=login&prompt=none",
        "max_age=-1",
        "max_age=2147483648",
        "redirect_uri=https://evil.invalid",
    ],
)
def test_login_rejects_untrusted_options(rp, query):
    response = rp[1].get("/login?" + query, follow_redirects=False)
    assert response.status_code == 400
