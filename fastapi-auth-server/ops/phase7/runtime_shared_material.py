#!/usr/bin/env python3
"""Create private synthetic inputs for the Phase 7 shared-state gate."""

from __future__ import annotations

import argparse
import json
import re
import secrets
import shlex
import stat
from pathlib import Path
from urllib.parse import quote

from runtime_material import read_example, write_private_json


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--example", type=Path, required=True)
    parser.add_argument("--private-dir", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--express-port", type=int, required=True)
    parser.add_argument("--fastapi-port", type=int, required=True)
    args = parser.parse_args()

    private_dir = args.private_dir.resolve()
    if not private_dir.is_dir() or stat.S_IMODE(private_dir.stat().st_mode) != 0o700:
        raise SystemExit("private directory must have exact mode 0700")
    if re.fullmatch(r"[a-z0-9][a-z0-9_]{0,29}", args.run_id) is None:
        raise SystemExit("run id must contain only letters, digits, and underscores")
    if args.express_port == args.fastapi_port or not all(
        1024 < port < 65536 for port in (args.express_port, args.fastapi_port)
    ):
        raise SystemExit("runtime ports must be distinct non-privileged ports")

    example = read_example(args.example)
    required_example = {
        "JWT_ACCESS_ALGORITHM",
        "JWT_ACCESS_PRIVATE_KEY",
        "JWT_ACCESS_PUBLIC_JWK",
        "JWT_ACCESS_KEY_ID",
        "AUTH_CLIENTS_JSON",
    }
    if not required_example.issubset(example):
        raise SystemExit("synthetic example is missing required signer or client policy")
    example["JWT_ACCESS_PRIVATE_KEY"] = example["JWT_ACCESS_PRIVATE_KEY"].replace("\\\\n", "\\n")

    database = f"phase7_shared_test_{args.run_id}"
    express_role = f"p7se_{args.run_id}"
    fastapi_role = f"p7sf_{args.run_id}"
    express_password = secrets.token_urlsafe(24)
    fastapi_password = secrets.token_urlsafe(24)
    refresh_secret = secrets.token_urlsafe(36)
    postgres_origin = "127.0.0.1:5433"
    redis_url = "redis://127.0.0.1:6380/13"
    express_database_url = (
        f"postgresql://{express_role}:{quote(express_password, safe='')}@"
        f"{postgres_origin}/{database}"
    )
    fastapi_node_database_url = (
        f"postgresql://{fastapi_role}:{quote(fastapi_password, safe='')}@"
        f"{postgres_origin}/{database}"
    )
    fastapi_python_database_url = fastapi_node_database_url.replace(
        "postgresql://", "postgresql+asyncpg://", 1
    )
    express_url = f"http://127.0.0.1:{args.express_port}"
    fastapi_url = f"http://127.0.0.1:{args.fastapi_port}"

    clients = json.loads(example["AUTH_CLIENTS_JSON"])
    clients = [client for client in clients if client.get("clientId") != "contract-fixture"]
    clients.append(
        {
            "clientId": "contract-fixture",
            "audience": "contract-fixture",
            "allowedRedirectUris": ["http://127.0.0.1:4101/auth/callback"],
            "allowedOrigins": ["http://127.0.0.1:4101"],
            "defaultRole": {"serviceKey": "contract-fixture", "name": "pending"},
        }
    )
    shared = dict(example)
    shared.update(
        {
            "NODE_ENV": "test",
            "JWT_ISSUER": "https://auth.financenow.kr",
            "JWT_AUDIENCE": "contract-fixture",
            "JWT_REFRESH_SECRET": refresh_secret,
            "AUTH_CLIENTS_JSON": json.dumps(clients, separators=(",", ":")),
            "CORS_ALLOWED_ORIGINS": "http://127.0.0.1:4101",
            "FRONTEND_REDIRECT_URL": "http://127.0.0.1:4101/auth/callback",
            "OAUTH_ENABLED_PROVIDERS": "",
            "GOOGLE_CLIENT_ID": "",
            "GOOGLE_CLIENT_SECRET": "",
            "NAVER_CLIENT_ID": "",
            "NAVER_CLIENT_SECRET": "",
            "KAKAO_CLIENT_ID": "",
            "KAKAO_CLIENT_SECRET": "",
            "MAIL_PROVIDER": "dev",
            "RESEND_API_KEY": "",
            "RESEND_ADMIN_KEY": "",
            "SMTP_HOST": "",
            "SMTP_USERNAME": "",
            "SMTP_PASSWORD": "",
        }
    )
    write_private_json(
        private_dir / "express-runtime.json",
        {
            **shared,
            "WISEACCT_PHASE7_EXPRESS_LOOPBACK": "1",
            "PORT": str(args.express_port),
            "DATABASE_URL": express_database_url,
            "REDIS_URL": redis_url,
        },
    )
    write_private_json(
        private_dir / "fastapi-runtime.json",
        {
            **shared,
            "PORT": str(args.fastapi_port),
            "DATABASE_URL": fastapi_python_database_url,
            "REDIS_URL": redis_url,
        },
    )
    write_private_json(
        private_dir / "shared-admin.json",
        {
            "DATABASE_URL": (
                "postgresql://fastapi_dev:synthetic-fastapi-db-only@127.0.0.1:5433/" + database
            )
        },
    )

    adapter_shared = {
        "CONTRACT_FIXTURE_MODE": "1",
        "CONTRACT_SERVER_MAIL_MODE": "dev",
        "CONTRACT_REDIS_ISOLATED_DB": "1",
        "CONTRACT_REFRESH_SECRET": refresh_secret,
        "CONTRACT_FIXTURE_EMAIL_DOMAIN": "example.invalid",
        "CONTRACT_FIXTURE_AUDIENCE": "contract-fixture",
        "CONTRACT_FIXTURE_CLIENT_ID": "contract-fixture",
        "CONTRACT_FIXTURE_REDIRECT_URI": "http://127.0.0.1:4101/auth/callback",
    }
    write_private_json(
        private_dir / "express-adapter.json",
        {
            **adapter_shared,
            "CONTRACT_BASE_URL": express_url,
            "CONTRACT_DATABASE_URL": express_database_url,
            "CONTRACT_REDIS_URL": redis_url,
        },
    )
    write_private_json(
        private_dir / "fastapi-adapter.json",
        {
            **adapter_shared,
            "CONTRACT_FASTAPI_RUNTIME": "1",
            "CONTRACT_BASE_URL": fastapi_url,
            "CONTRACT_DATABASE_URL": fastapi_node_database_url,
            "CONTRACT_REDIS_URL": redis_url,
        },
    )

    shell_values = {
        "P7_SHARED_DATABASE": database,
        "P7_EXPRESS_ROLE": express_role,
        "P7_FASTAPI_ROLE": fastapi_role,
        "P7_EXPRESS_PASSWORD": express_password,
        "P7_FASTAPI_PASSWORD": fastapi_password,
        "P7_EXPRESS_NODE_DATABASE_URL": express_database_url,
        "P7_FASTAPI_NODE_DATABASE_URL": fastapi_node_database_url,
        "P7_FASTAPI_PYTHON_DATABASE_URL": fastapi_python_database_url,
        "P7_SHARED_REDIS_URL": redis_url,
        "P7_EXPRESS_URL": express_url,
        "P7_FASTAPI_URL": fastapi_url,
    }
    material = private_dir / "material.sh"
    material.write_text(
        "".join(f"{key}={shlex.quote(value)}\n" for key, value in shell_values.items()),
        encoding="utf-8",
    )
    material.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
