"""Fantra role keys: ``temis:*`` is the retired legacy name of ``fantra:*``.

Fantra (prod and develop) accepts both keys and folds them into one, so SSO now
writes only ``fantra:pending`` / ``fantra:user``. A request for the legacy
``temis:pending`` / ``temis:user`` (old client config, old invitations, old admin
pages) is stored under the ``fantra`` key instead. ``temis:admin`` is left alone:
new grants of it are refused elsewhere.
"""

from __future__ import annotations

LEGACY_FANTRA_SERVICE_KEY = "temis"
FANTRA_SERVICE_KEY = "fantra"
FANTRA_SERVICE_KEYS = frozenset({LEGACY_FANTRA_SERVICE_KEY, FANTRA_SERVICE_KEY})
FANTRA_DEFAULT_ROLE_NAMES = frozenset({"pending", "user"})


def is_fantra_service(service_key: str) -> bool:
    return service_key in FANTRA_SERVICE_KEYS


def canonical_role(service_key: str, name: str) -> tuple[str, str]:
    """Return the role SSO actually stores: legacy ``temis`` pending/user become ``fantra``."""

    if service_key == LEGACY_FANTRA_SERVICE_KEY and name in FANTRA_DEFAULT_ROLE_NAMES:
        return (FANTRA_SERVICE_KEY, name)
    return (service_key, name)


def canonical_roles(roles: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Map roles to their stored form, keeping order and dropping duplicates."""

    result: list[tuple[str, str]] = []
    for service_key, name in roles:
        role = canonical_role(service_key, name)
        if role not in result:
            result.append(role)
    return result


def twin_role(service_key: str, name: str) -> tuple[str, str] | None:
    """Return the same Fantra pending/user role under the other key, else None.

    Used only when removing a role, so a user who still holds a legacy ``temis``
    row loses both. Nothing grants the twin any more.
    """

    if not is_fantra_service(service_key) or name not in FANTRA_DEFAULT_ROLE_NAMES:
        return None
    other = (
        FANTRA_SERVICE_KEY if service_key == LEGACY_FANTRA_SERVICE_KEY else LEGACY_FANTRA_SERVICE_KEY
    )
    return (other, name)
