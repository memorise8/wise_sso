"""Dormant operator commands for an eventual FastAPI cutover.

Nothing in this package is scheduled or invoked by the application runtime.  Express
and Prisma remain the active production operations owner until an approved cutover.

Audit retention, refresh-token cleanup, and first-admin bootstrap are mirrored only as
dormant cutover-continuity modules. Seed, backfill, merge, and migration commands are
intentionally not ported.
"""
