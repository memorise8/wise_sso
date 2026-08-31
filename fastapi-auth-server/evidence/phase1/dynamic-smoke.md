# Phase 1 provisional dynamic smoke

- Status: `PROVISIONAL`
- Captured at: `2026-08-31T01:26:50Z`
- Revalidated after the Redis mount fix: `2026-08-31T01:34:58Z`
- Launcher: `./ops/dev-compose.sh up .env.example`
- App image: `sha256:4d89abc2d6fc2ff1ab2c9dcdd66272e635644ba144f5e6253239392d6ee24bc1`
- PostgreSQL image: `postgres@sha256:23e88eb049fd5d54894d70100df61d38a49ed97909263f79d4ff4c30a5d5fca2`
- Redis image: `redis@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99`

## Before

The exact Compose project label queries returned no FastAPI candidate containers,
networks, or volumes.

## Running resource snapshot

```text
wiseacct-sso-fastapi-dev-app|healthy|127.0.0.1:4001->4001/tcp
wiseacct-sso-fastapi-dev-postgres|healthy|127.0.0.1:5433->5432/tcp
wiseacct-sso-fastapi-dev-redis|healthy|127.0.0.1:6380->6379/tcp
wiseacct-sso-fastapi-dev-network
wiseacct-sso-fastapi-dev-postgres-data
```

The Redis image's declared `/data` volume is explicitly replaced with
`tmpfs=/data:rw,noexec,nosuid,size=64m`. Runtime inspection reported no Redis Docker
volume mounts and exactly that tmpfs. The guarded launcher independently compared all
runtime container ports, mounts, and networks with the expected manifest before
returning success. It also compared the complete project-labeled container, network,
and volume name sets so detached or additional project resources cannot be omitted.

The application container ran as `fastapi-sso`; all three candidate containers had
restart count `0`. The launcher waited until all health checks completed before
returning success.

## Endpoint snapshot

```text
GET http://127.0.0.1:4001/healthz
{"status":"ok"}
status=200

GET http://127.0.0.1:4001/readyz
{"status":"unavailable"}
status=503
```

`/readyz=503` is the explicit Phase 1 default until Phase 2 installs real dependency
checks. It is not production-readiness evidence.

The existing Express endpoint remained `200`. Its app, PostgreSQL, and Redis container
IDs, start timestamps, health, and restart counts remained unchanged.

## Cleanup snapshot

`./ops/dev-compose.sh down .env.example` used `down --volumes --remove-orphans` and
removed the three candidate containers, candidate network, and exact synthetic-only
PostgreSQL volume. Subsequent exact Compose project label queries returned no candidate
containers, networks, or volumes. No anonymous Redis volume was created. Existing
Express, PostgreSQL, and Redis remained healthy with restart count `0`, and Express
`/healthz` remained `200`.

The launcher has a regression fixture proving that even a partial `compose up` failure
invokes the same scoped cleanup before returning failure.
