# Phase 3 provisional runtime smoke

The latest guarded run completed on 2026-08-31 at approximately 12:32 KST.

| Check | Result |
| --- | --- |
| Candidate project | Exact guarded project `wiseacct-sso-fastapi-dev` |
| Candidate image | `sha256:e06b56598d2dc8add285a1c24802d2fe6a308219343b8102884f3d0d04cae391` |
| Runtime identity | non-root `fastapi-sso`, healthy, restart count `0` |
| Proxy headers | Uvicorn `--no-proxy-headers` until ingress proof exists |
| Health/readiness | `/healthz` `200`; `/readyz` `200` against isolated PostgreSQL |
| Discovery | JWKS and OIDC endpoints `200` with five-minute public caching |
| Static surface | portal, dashboard, and asset requests `200`; served asset hash matched source; HTML and asset conditional requests returned `304` |
| Route parity | literal asset mounts, encoded filename handling, case-preserving asset-root redirects, and trailing-slash behavior matched the captured Express contracts |
| Error surface | unknown route and unsupported method returned Express-compatible JSON `404` |
| Security headers | all twelve observed Helmet-compatible headers present on JSON errors |
| CORS / runtime headers | allowed-origin `OPTIONS` returned empty `204`; JSON charset was explicit; Uvicorn server and access-log headers/output were disabled |
| Log redaction | a synthetic token-bearing query was served without the token value appearing in container logs; the metric retained only the normalized route |
| Express | unchanged and `/healthz` remained `200` |

After the smoke, exact project-label queries returned zero candidate containers,
networks, and volumes. No production route, container, database, Redis namespace,
credential, or volume was changed.

This is a provisional development observation only. Token cross-verification, ingress
client-IP parity, canonical replay, and production gates remain deferred.
