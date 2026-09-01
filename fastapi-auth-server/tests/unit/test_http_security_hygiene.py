import pytest

from wiseacct_sso.api.dependencies import (
    MAX_AUDIT_IP_ADDRESS_LENGTH,
    MAX_AUDIT_USER_AGENT_LENGTH,
    request_audit_context,
)
from wiseacct_sso.api.middleware import _requires_no_store
from wiseacct_sso.application.auth import RequestAuditContext


def test_audit_context_normalizes_the_frozen_first_forwarded_hop_contract() -> None:
    context = request_audit_context(
        forwarded_for=" 203.0.113.8 , 10.0.0.2 ",
        user_agent="  test browser  ",
        client_address="192.0.2.1",
    )

    assert context == RequestAuditContext("203.0.113.8", "test browser")


@pytest.mark.parametrize("control", ["\x00", "\t", "\n", "\x7f", "\x85"])
def test_audit_context_rejects_control_character_values(control: str) -> None:
    context = request_audit_context(
        forwarded_for=f"203.0.113.8{control}spoofed",
        user_agent=f"browser{control}injected",
        client_address="192.0.2.1",
    )

    assert context == RequestAuditContext("192.0.2.1", None)


def test_audit_context_bounds_stored_values_without_truncating_an_address() -> None:
    context = request_audit_context(
        forwarded_for="x" * (MAX_AUDIT_IP_ADDRESS_LENGTH + 1),
        user_agent="agent/" + "x" * MAX_AUDIT_USER_AGENT_LENGTH,
        client_address="192.0.2.1",
    )

    assert context.ip_address == "192.0.2.1"
    assert (
        context.user_agent
        == ("agent/" + "x" * MAX_AUDIT_USER_AGENT_LENGTH)[:MAX_AUDIT_USER_AGENT_LENGTH]
    )


@pytest.mark.parametrize(
    "path",
    [
        "/auth/login",
        "/AUTH/REFRESH/",
        "/auth/google/callback",
        "/users/me",
        "/admin/users",
        "/admin/audit-logs",
        "/manage-api/users/target/roles",
    ],
)
def test_sensitive_response_paths_require_no_store(path: str) -> None:
    assert _requires_no_store(path) is True


@pytest.mark.parametrize(
    "path",
    [
        "/.well-known/jwks.json",
        "/.well-known/openid-configuration",
        "/auth/callback",
        "/auth/callback/",
        "/admin/dashboard",
        "/manage/dashboard",
        "/assets/auth.js",
        "/healthz",
    ],
)
def test_public_metadata_and_static_paths_keep_their_cache_contract(path: str) -> None:
    assert _requires_no_store(path) is False
