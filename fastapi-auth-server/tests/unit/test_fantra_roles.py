from wiseacct_sso.domain.fantra_roles import canonical_role, canonical_roles, twin_role


def test_legacy_temis_pending_and_user_are_stored_as_fantra() -> None:
    assert canonical_role("temis", "user") == ("fantra", "user")
    assert canonical_role("temis", "pending") == ("fantra", "pending")
    assert canonical_role("fantra", "user") == ("fantra", "user")


def test_admin_and_other_services_keep_their_key() -> None:
    assert canonical_role("temis", "admin") == ("temis", "admin")
    assert canonical_role("fantra", "admin") == ("fantra", "admin")
    assert canonical_role("gitlab", "user") == ("gitlab", "user")


def test_canonical_roles_keeps_order_and_drops_duplicates() -> None:
    assert canonical_roles([("gitlab", "user"), ("fantra", "user"), ("temis", "user")]) == [
        ("gitlab", "user"),
        ("fantra", "user"),
    ]


def test_twin_role_is_only_for_removing_legacy_rows() -> None:
    assert twin_role("fantra", "user") == ("temis", "user")
    assert twin_role("temis", "pending") == ("fantra", "pending")
    assert twin_role("fantra", "admin") is None
    assert twin_role("gitlab", "user") is None
