"""Explicit persistence primitives for the Prisma-owned PostgreSQL schema."""

from wiseacct_sso.persistence.database import Database, database_only_transaction

__all__ = ["Database", "database_only_transaction"]
