#!/usr/bin/env python3
"""Create private synthetic runtime and adapter inputs for a Phase 7 run."""

from __future__ import annotations

import argparse
import json
import re
import secrets
import shlex
import stat
from pathlib import Path
from urllib.parse import quote


def read_example(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"invalid environment example line {line_number}")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key] = value
    return values


def write_private_json(path: Path, document: dict[str, str]) -> None:
    path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


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
    # Compose consumes the checked-in quoted example and removes one escaping
    # layer. Host processes receive an exact environment object, so reproduce
    # that single layer here before both runtimes validate the PEM.
    example["JWT_ACCESS_PRIVATE_KEY"] = example["JWT_ACCESS_PRIVATE_KEY"].replace("\\\\n", "\\n")

    express_database = f"phase7_express_test_{args.run_id}"
    fastapi_database = f"phase7_fastapi_test_{args.run_id}"
    express_role = f"p7e_{args.run_id}"
    fastapi_role = f"p7f_{args.run_id}"
    express_password = secrets.token_urlsafe(24)
    fastapi_password = secrets.token_urlsafe(24)
    refresh_secret = secrets.token_urlsafe(36)
    postgres_origin = "127.0.0.1:5433"
    redis_origin = "127.0.0.1:6380"
    express_node_database_url = (
        f"postgresql://{express_role}:{quote(express_password, safe='')}@"
        f"{postgres_origin}/{express_database}"
    )
    fastapi_node_database_url = (
        f"postgresql://{fastapi_role}:{quote(fastapi_password, safe='')}@"
        f"{postgres_origin}/{fastapi_database}"
    )
    fastapi_python_database_url = fastapi_node_database_url.replace(
        "postgresql://", "postgresql+asyncpg://", 1
    )
    express_url = f"http://127.0.0.1:{args.express_port}"
    fastapi_url = f"http://127.0.0.1:{args.fastapi_port}"
    express_redis_url = f"redis://{redis_origin}/13"
    fastapi_redis_url = f"redis://{redis_origin}/14"

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
    express_env = {
        **shared,
        "WISEACCT_PHASE7_EXPRESS_LOOPBACK": "1",
        "PORT": str(args.express_port),
        "DATABASE_URL": express_node_database_url,
        "REDIS_URL": express_redis_url,
    }
    fastapi_env = {
        **shared,
        "PORT": str(args.fastapi_port),
        "DATABASE_URL": fastapi_python_database_url,
        "REDIS_URL": fastapi_redis_url,
    }
    write_private_json(private_dir / "express-runtime.json", express_env)
    write_private_json(private_dir / "fastapi-runtime.json", fastapi_env)
    admin_prefix = "postgresql://fastapi_dev:synthetic-fastapi-db-only@127.0.0.1:5433/"
    write_private_json(
        private_dir / "express-admin.json", {"DATABASE_URL": admin_prefix + express_database}
    )
    write_private_json(
        private_dir / "fastapi-admin.json", {"DATABASE_URL": admin_prefix + fastapi_database}
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
    express_adapter = {
        **adapter_shared,
        "CONTRACT_BASE_URL": express_url,
        "CONTRACT_DATABASE_URL": express_node_database_url,
        "CONTRACT_REDIS_URL": express_redis_url,
    }
    fastapi_adapter = {
        **adapter_shared,
        "CONTRACT_FASTAPI_RUNTIME": "1",
        "CONTRACT_BASE_URL": fastapi_url,
        "CONTRACT_DATABASE_URL": fastapi_node_database_url,
        "CONTRACT_REDIS_URL": fastapi_redis_url,
    }
    write_private_json(private_dir / "express-adapter.json", express_adapter)
    write_private_json(private_dir / "fastapi-adapter.json", fastapi_adapter)

    shell_values = {
        "P7_EXPRESS_DATABASE": express_database,
        "P7_FASTAPI_DATABASE": fastapi_database,
        "P7_EXPRESS_ROLE": express_role,
        "P7_FASTAPI_ROLE": fastapi_role,
        "P7_EXPRESS_PASSWORD": express_password,
        "P7_FASTAPI_PASSWORD": fastapi_password,
        "P7_EXPRESS_NODE_DATABASE_URL": express_node_database_url,
        "P7_FASTAPI_NODE_DATABASE_URL": fastapi_node_database_url,
        "P7_FASTAPI_PYTHON_DATABASE_URL": fastapi_python_database_url,
        "P7_EXPRESS_REDIS_URL": express_redis_url,
        "P7_FASTAPI_REDIS_URL": fastapi_redis_url,
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
