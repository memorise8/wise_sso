"""Validate production settings and exact internal/external OIDC authorization policy."""

import argparse

from wiseacct_sso.config import Settings

REQUIRED_POLICIES = {
    "gitlab-temis": ({"EMPLOYEE", "EXTERNAL"}, {("gitlab", "user")}),
    # agent-hub grants guests per-project access itself, so it opts out of the role gate.
    "agent-hub-dash": ({"EMPLOYEE", "CUSTOMER", "EXTERNAL"}, {("agent-hub", "user")}),
    "fantra-oidc": ({"CUSTOMER", "EMPLOYEE"}, {("temis", "user")}),
}


def validate_policy(settings: Settings) -> None:
    if settings.node_env != "production" or not settings.oidc_enabled:
        raise ValueError("Production OIDC must be enabled")
    clients = {c.client_id: c for c in settings.oidc_clients}
    for identifier, (types, roles) in REQUIRED_POLICIES.items():
        client = clients.get(identifier)
        if (
            client is None
            or set(client.allowed_user_types or ()) != types
            or {(r.service_key, r.name) for r in client.required_roles} != roles
            or set(client.groups_service_keys) != {key for key, _ in roles}
            or client.allow_without_required_role != (identifier == "agent-hub-dash")
        ):
            raise ValueError("Production client authorization policy mismatch")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file")
    args = parser.parse_args()
    try:
        validate_policy(Settings(_env_file=args.env_file))  # type: ignore[call-arg]
    except Exception:
        raise SystemExit("FAIL: invalid production configuration (values withheld)") from None
    print("PASS: production settings and explicit client policies validated")


if __name__ == "__main__":
    main()
