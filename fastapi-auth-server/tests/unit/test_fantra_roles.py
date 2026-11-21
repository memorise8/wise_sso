from wiseacct_sso.domain.fantra_roles import mirrored_roles, twin_role, with_twins


def test_fantra_pending_and_user_are_mirrored_across_both_keys() -> None:
    assert twin_role("temis", "user") == ("fantra", "user")
    assert twin_role("fantra", "pending") == ("temis", "pending")
    assert mirrored_roles("fantra", "user") == (("temis", "user"), ("fantra", "user"))


def test_admin_and_other_services_are_not_mirrored() -> None:
    assert twin_role("fantra", "admin") is None
    assert twin_role("temis", "admin") is None
    assert twin_role("gitlab", "user") is None
    assert mirrored_roles("gitlab", "user") == (("gitlab", "user"),)


def test_with_twins_keeps_order_and_drops_duplicates() -> None:
    assert with_twins([("gitlab", "user"), ("fantra", "user"), ("temis", "user")]) == [
        ("gitlab", "user"),
        ("temis", "user"),
        ("fantra", "user"),
    ]
