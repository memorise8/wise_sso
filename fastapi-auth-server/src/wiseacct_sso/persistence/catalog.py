"""Deterministic catalog representation used by the live parity integration suite."""

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, cast

from sqlalchemy import DefaultClause, Enum, MetaData, inspect
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Connection, Dialect
from sqlalchemy.ext.asyncio import AsyncConnection


@dataclass(frozen=True, order=True, slots=True)
class CatalogEntry:
    category: str
    name: str
    definition: str


@dataclass(frozen=True, slots=True)
class CatalogDiff:
    missing: tuple[CatalogEntry, ...]
    unexpected: tuple[CatalogEntry, ...]

    @property
    def matches(self) -> bool:
        return not self.missing and not self.unexpected


def normalize_definition(value: str) -> str:
    """Normalize insignificant catalog formatting without changing identifiers."""

    normalized = re.sub(r"\s+", " ", value.strip()).replace("::character varying", "::text")
    normalized = normalized.replace('::"UserStatus"', "")
    return re.sub(r"('(?:[^']|'')*')::text", r"\1", normalized)


def normalize_catalog(entries: Iterable[CatalogEntry]) -> tuple[CatalogEntry, ...]:
    return tuple(
        sorted(
            {
                CatalogEntry(entry.category, entry.name, normalize_definition(entry.definition))
                for entry in entries
            }
        )
    )


def diff_catalog(expected: Iterable[CatalogEntry], actual: Iterable[CatalogEntry]) -> CatalogDiff:
    expected_set = set(normalize_catalog(expected))
    actual_set = set(normalize_catalog(actual))
    return CatalogDiff(
        missing=tuple(sorted(expected_set - actual_set)),
        unexpected=tuple(sorted(actual_set - expected_set)),
    )


def metadata_catalog(metadata: MetaData) -> tuple[CatalogEntry, ...]:
    """Render explicit SQLAlchemy metadata into the same stable catalog vocabulary."""

    dialect = cast(Dialect, postgresql.dialect())  # type: ignore[no-untyped-call]
    entries: list[CatalogEntry] = []
    enums: set[tuple[str, tuple[str, ...]]] = set()
    for table in metadata.sorted_tables:
        entries.append(CatalogEntry("table", table.name, "public"))
        for column in table.columns:
            column_type = column.type.compile(dialect=dialect)
            default_clause = cast(DefaultClause | None, column.server_default)
            default = "" if default_clause is None else str(default_clause.arg)
            definition = (
                f"type={column_type};nullable={str(column.nullable).lower()};default={default}"
            )
            entries.append(CatalogEntry("column", f"{table.name}.{column.name}", definition))
            if isinstance(column.type, Enum):
                if column.type.name is None:
                    raise ValueError(f"enum on {table.name}.{column.name} must have a name")
                enums.add((str(column.type.name), tuple(column.type.enums)))

        if table.primary_key.name is not None:
            columns = ",".join(column.name for column in table.primary_key.columns)
            entries.append(
                CatalogEntry("primary_key", str(table.primary_key.name), f"{table.name}({columns})")
            )
        for index in table.indexes:
            if index.name is None:
                raise ValueError(f"index on {table.name} must have an explicit name")
            columns = ",".join(column.name for column in index.columns)
            entries.append(
                CatalogEntry(
                    "index",
                    str(index.name),
                    f"{table.name}({columns});unique={str(index.unique).lower()}",
                )
            )
        for foreign_key in table.foreign_key_constraints:
            if foreign_key.name is None:
                raise ValueError(f"foreign key on {table.name} must have an explicit name")
            local = ",".join(column.name for column in foreign_key.columns)
            remote = ",".join(element.target_fullname for element in foreign_key.elements)
            entries.append(
                CatalogEntry(
                    "foreign_key",
                    str(foreign_key.name),
                    (
                        f"{table.name}({local})->{remote};"
                        f"ondelete={foreign_key.ondelete};onupdate={foreign_key.onupdate}"
                    ),
                )
            )
    for enum_name, values in enums:
        entries.append(CatalogEntry("enum", enum_name, ",".join(values)))
    return normalize_catalog(entries)


def _database_catalog(sync_connection: Connection) -> tuple[CatalogEntry, ...]:
    """Read a PostgreSQL catalog through SQLAlchemy's reflection boundary."""

    inspector = inspect(sync_connection)
    dialect = cast(Dialect, postgresql.dialect())  # type: ignore[no-untyped-call]
    entries: list[CatalogEntry] = []
    for table_name in inspector.get_table_names(schema="public"):
        entries.append(CatalogEntry("table", table_name, "public"))
        for raw_column in cast(list[dict[str, Any]], inspector.get_columns(table_name, "public")):
            column_type = raw_column["type"].compile(dialect=dialect)
            default = raw_column.get("default") or ""
            definition = (
                f"type={column_type};nullable={str(raw_column['nullable']).lower()};"
                f"default={default}"
            )
            entries.append(CatalogEntry("column", f"{table_name}.{raw_column['name']}", definition))

        primary_key = cast(dict[str, Any], inspector.get_pk_constraint(table_name, "public"))
        primary_key_name = primary_key.get("name")
        if primary_key_name:
            columns = ",".join(primary_key["constrained_columns"])
            entries.append(
                CatalogEntry("primary_key", primary_key_name, f"{table_name}({columns})")
            )
        for index in cast(list[dict[str, Any]], inspector.get_indexes(table_name, "public")):
            index_name = index.get("name")
            index_columns = index.get("column_names")
            if index_name and index_columns and not index.get("duplicates_constraint"):
                entries.append(
                    CatalogEntry(
                        "index",
                        index_name,
                        (
                            f"{table_name}({','.join(index_columns)});"
                            f"unique={str(index['unique']).lower()}"
                        ),
                    )
                )
        for foreign_key in cast(
            list[dict[str, Any]], inspector.get_foreign_keys(table_name, "public")
        ):
            foreign_key_name = foreign_key.get("name")
            if not foreign_key_name:
                continue
            local = ",".join(foreign_key["constrained_columns"])
            remote = ",".join(
                f"{foreign_key['referred_table']}.{column}"
                for column in foreign_key["referred_columns"]
            )
            options = foreign_key.get("options", {})
            entries.append(
                CatalogEntry(
                    "foreign_key",
                    foreign_key_name,
                    (
                        f"{table_name}({local})->{remote};"
                        f"ondelete={options.get('ondelete')};onupdate={options.get('onupdate')}"
                    ),
                )
            )

    get_enums = getattr(inspector, "get_enums", None)
    if get_enums is None:
        raise RuntimeError("PostgreSQL inspector does not expose enum catalog data")
    for enum in cast(list[dict[str, Any]], get_enums(schema="public")):
        entries.append(CatalogEntry("enum", enum["name"], ",".join(enum["labels"])))
    return normalize_catalog(entries)


async def inspect_database_catalog(connection: AsyncConnection) -> tuple[CatalogEntry, ...]:
    """Return a normalized snapshot of the live Prisma-owned PostgreSQL catalog."""

    return await connection.run_sync(_database_catalog)
