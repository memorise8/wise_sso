from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_python_runtime_does_not_expose_schema_migration_operations() -> None:
    source_root = ROOT / "src" / "wiseacct_sso"
    source = "\n".join(path.read_text() for path in source_root.rglob("*.py"))
    forbidden = ("create_all(", "drop_all(", "alembic", "CREATE TABLE", "DROP TABLE")
    assert all(token not in source for token in forbidden)
