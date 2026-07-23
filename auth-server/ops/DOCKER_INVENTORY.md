# Docker Inventory

Last checked: 2026-07-23

## Auth Server

Owned by this repository:

| Container | Compose project | Compose file | Purpose | Notes |
| --- | --- | --- | --- | --- |
| `auth-server-postgres-1` | `auth-server` | `/home/ruci/repo/wiseacct_sso/auth-server/docker-compose.yml` | Auth Server PostgreSQL | Stores auth/account/session/audit data only. |
| `auth-server-redis-1` | `auth-server` | `/home/ruci/repo/wiseacct_sso/auth-server/docker-compose.yml` | Auth Server Redis | Stores OAuth state and one-time handoff code state. |
| `auth-server-app-1` | `auth-server` | `/home/ruci/repo/wiseacct_sso/auth-server/docker-compose.yml` | Auth Server Node app | Created when running `docker compose up -d app`. |

Use this directory to control Auth Server containers:

```sh
cd /home/ruci/repo/wiseacct_sso/auth-server
docker compose up -d postgres redis
docker compose up -d app
docker compose ps
docker compose logs -f app
docker compose down
```

`docker compose down` stops the Auth Server containers but keeps the Postgres volume.
`docker compose down -v` deletes Auth Server database data and should only be used for an intentional reset.

## Other Running Containers Observed

Do not stop these as part of Auth Server maintenance unless their owning service is intentionally being stopped.

| Container | Compose project | Compose file | Purpose inferred from labels |
| --- | --- | --- | --- |
| `wmemo-pilot-gateway-1` | `wmemo-pilot` | `/home/ruci/repo/wmemo/infra/docker-compose.yml` | Wmemo pilot gateway, published on `192.168.0.4:3100`. |
| `wmemo-pilot-memo-api-1` | `wmemo-pilot` | `/home/ruci/repo/wmemo/infra/docker-compose.yml` | Wmemo pilot API, internal Docker port only. |
| `wmemo-pilot-postgres-1` | `wmemo-pilot` | `/home/ruci/repo/wmemo/infra/docker-compose.yml` | Wmemo pilot PostgreSQL. |
| `wmemo-pilot-redis-1` | `wmemo-pilot` | `/home/ruci/repo/wmemo/infra/docker-compose.yml` | Wmemo pilot Redis. |
| `wmemo-memoapi-test-postgres` | none found | none found | Standalone/local test PostgreSQL published on `127.0.0.1:55432`. |
| `crawler-poc` | `frwaler` | `/home/yeosun.lim/frwaler/docker-compose.yml` | Separate crawler POC app. |
| `grafana` | `operate` | `/home/ruci/operate/docker-compose.yaml` | Monitoring UI. |
| `node-exporter` | `operate` | `/home/ruci/operate/docker-compose.yaml` | Host metrics exporter. |

## Binding Policy

The Compose file always binds PostgreSQL and Redis to loopback:

```sh
127.0.0.1:${AUTH_DB_PORT:-5432}:5432
127.0.0.1:${AUTH_REDIS_PORT:-6379}:6379
AUTH_HTTP_HOST=127.0.0.1
```

If Cloudflare Tunnel runs on another host and must reach this server directly, expose only the Auth Server HTTP port on the private interface:

```sh
AUTH_HTTP_HOST=192.168.0.4
AUTH_HTTP_PORT=4000
```

Keep PostgreSQL and Redis on `127.0.0.1`. Only the HTTP service should be exposed to Cloudflare Tunnel or a private reverse proxy.
