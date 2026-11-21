"""Fantra role-key transition: ``temis:*`` is the legacy name of ``fantra:*``.

While Fantra accepts both keys, SSO writes both so either Fantra build and either
OIDC client policy keeps working. Once ``temis:*`` is retired this module shrinks
to the ``fantra`` constant.
"""

from __future__ import annotations

LEGACY_FANTRA_SERVICE_KEY = "temis"
FANTRA_SERVICE_KEY = "fantra"
FANTRA_SERVICE_KEYS = frozenset({LEGACY_FANTRA_SERVICE_KEY, FANTRA_SERVICE_KEY})
FANTRA_DEFAULT_ROLE_NAMES = frozenset({"pending", "user"})


def is_fantra_service(service_key: str) -> bool:
    return service_key in FANTRA_SERVICE_KEYS


def twin_role(service_key: str, name: str) -> tuple[str, str] | None:
    """Return the same Fantra role under the other key, or None when not mirrored.

    Only ``pending`` and ``user`` are mirrored: new ``temis:admin`` grants are
    disabled, and Fantra treats ``fantra:admin`` alone as its admin role.
    """

    if not is_fantra_service(service_key) or name not in FANTRA_DEFAULT_ROLE_NAMES:
        return None
    other = (
        FANTRA_SERVICE_KEY
        if service_key == LEGACY_FANTRA_SERVICE_KEY
        else LEGACY_FANTRA_SERVICE_KEY
    )
    return (other, name)


def mirrored_roles(service_key: str, name: str) -> tuple[tuple[str, str], ...]:
    """Return the role plus its twin (if any), legacy key first."""

    twin = twin_role(service_key, name)
    if twin is None:
        return ((service_key, name),)
    return ((LEGACY_FANTRA_SERVICE_KEY, name), (FANTRA_SERVICE_KEY, name))


def with_twins(roles: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Expand roles with their Fantra twins, keeping order and dropping duplicates."""

    expanded: list[tuple[str, str]] = []
    for service_key, name in roles:
        for role in mirrored_roles(service_key, name):
            if role not in expanded:
                expanded.append(role)
    return expanded
