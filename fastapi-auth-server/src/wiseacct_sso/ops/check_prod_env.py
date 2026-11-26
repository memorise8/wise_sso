"""Validate production settings and exact internal/external OIDC authorization policy."""

import argparse

from wiseacct_sso.config import Settings

Role = tuple[str, str]
# Each accepted (requiredRoles, groupsServiceKeys) pair for a client.
RolePolicy = tuple[frozenset[Role], frozenset[str]]


def _single(role: Role) -> RolePolicy:
    return frozenset({role}), frozenset({role[0]})


# temis is the retired name of fantra (domain.fantra_roles): fantra-oidc must require
# fantra:user, and may still project the temis group key until the client drops it.
_FANTRA_POLICIES: frozenset[RolePolicy] = frozenset(
    {
        _single(("fantra", "user")),
        (frozenset({("fantra", "user")}), frozenset({"temis", "fantra"})),
    }
)

REQUIRED_POLICIES: dict[str, tuple[set[str], frozenset[RolePolicy]]] = {
    "gitlab-temis": ({"EMPLOYEE", "EXTERNAL"}, frozenset({_single(("gitlab", "user"))})),
    # agent-hub grants guests per-project access itself, so it opts out of the role gate.
    "agent-hub-dash": (
        {"EMPLOYEE", "CUSTOMER", "EXTERNAL"},
        frozenset({_single(("agent-hub", "user"))}),
    ),
    "fantra-oidc": ({"CUSTOMER", "EMPLOYEE"}, _FANTRA_POLICIES),
}


def validate_policy(settings: Settings) -> None:
    if settings.node_env != "production" or not settings.oidc_enabled:
        raise ValueError("Production OIDC must be enabled")
    clients = {c.client_id: c for c in settings.oidc_clients}
    for identifier, (types, policies) in REQUIRED_POLICIES.items():
        client = clients.get(identifier)
        if (
            client is None
            or set(client.allowed_user_types or ()) != types
            or (
                frozenset((r.service_key, r.name) for r in client.required_roles),
                frozenset(client.groups_service_keys),
            )
            not in policies
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
