"""Dormant operator commands for an eventual FastAPI cutover.

Nothing in this package is scheduled or invoked by the application runtime.  Express
and Prisma remain the active production operations owner until an approved cutover.

Audit retention, refresh-token cleanup, first-admin bootstrap, default-role backfill,
and split-identity merge are dormant cutover-continuity modules. Seed and migration
commands remain with the existing toolchain; Prisma is the sole schema authority.
"""
