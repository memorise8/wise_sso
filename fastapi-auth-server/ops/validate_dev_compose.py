#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

KNOWN_ENV_KEYS = {
    "ACCESS_TOKEN_EXPIRES_IN",
    "AUTH_CLIENTS_JSON",
    "AUTH_DB_ADMIN_PASSWORD",
    "AUTH_DB_NAME",
    "AUTH_DB_PASSWORD",
    "AUTH_DB_USER",
    "AUTH_RATE_LIMIT_MAX_REQUESTS",
    "AUTH_RATE_LIMIT_WINDOW_SECONDS",
    "COMPANY_ALLOWED_EMAIL_DOMAIN",
    "CORS_ALLOWED_ORIGINS",
    "DATABASE_URL",
    "FRONTEND_REDIRECT_URL",
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
    "GOOGLE_REDIRECT_URI",
    "JWT_ACCESS_ALGORITHM",
    "JWT_ACCESS_KEY_ID",
    "JWT_ACCESS_PRIVATE_KEY",
    "JWT_ACCESS_PUBLIC_JWK",
    "JWT_AUDIENCE",
    "JWT_ISSUER",
    "JWT_REFRESH_SECRET",
    "KAKAO_CLIENT_ID",
    "KAKAO_CLIENT_SECRET",
    "KAKAO_REDIRECT_URI",
    "MAIL_FROM",
    "MAIL_PROVIDER",
    "MAIL_REPLY_TO",
    "NAVER_CLIENT_ID",
    "NAVER_CLIENT_SECRET",
    "NAVER_REDIRECT_URI",
    "NODE_ENV",
    "OAUTH_ENABLED_PROVIDERS",
    "PASSWORD_MIN_LENGTH",
    "PORT",
    "REDIS_URL",
    "REFRESH_TOKEN_EXPIRES_IN_DAYS",
    "RESEND_ADMIN_KEY",
    "RESEND_API_KEY",
    "SMTP_HOST",
    "SMTP_PASSWORD",
    "SMTP_PORT",
    "SMTP_USERNAME",
}
SECRET_KEYS = {
    "AUTH_DB_ADMIN_PASSWORD",
    "AUTH_DB_PASSWORD",
    "GOOGLE_CLIENT_SECRET",
    "JWT_REFRESH_SECRET",
    "KAKAO_CLIENT_SECRET",
    "NAVER_CLIENT_SECRET",
    "RESEND_ADMIN_KEY",
    "RESEND_API_KEY",
    "SMTP_PASSWORD",
}
SYNTHETIC_PRIVATE_KEY_SHA256 = "43c202e873481963082973f4b4fc4d4542dd1ddf34c97529e99dcfbd0c162889"
SYNTHETIC_MODULUS_SHA256 = "6bf40596efda54b90a608bd5ee383e6a44b47089bdd09394b713c8cbca0c0ecd"


def fail(message: str) -> None:
    raise ValueError(f"PROVISIONAL guarded launcher: {message}")


def parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text().splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            fail(f"invalid env syntax on line {line_number}")
        key, raw_value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or key in values:
            fail(f"invalid or duplicate env key on line {line_number}")
        value = raw_value
        if len(value) >= 2 and value[0] == value[-1] == "'":
            value = value[1:-1]
        elif len(value) >= 2 and value[0] == value[-1] == '"':
            try:
                value = json.loads(value)
            except json.JSONDecodeError as error:
                fail(f"invalid quoted env value on line {line_number}: {error.msg}")
        values[key] = value
    return values


def validate_env(path: Path) -> dict[str, str]:
    if path.name != ".env.example" and not path.name.endswith((".fastapi-dev", ".fastapi-dev.env")):
        fail("env filename must be .env.example or explicitly FastAPI-dev")
    values = parse_env(path)
    missing = KNOWN_ENV_KEYS - values.keys()
    unknown = values.keys() - KNOWN_ENV_KEYS
    if missing or unknown:
        fail(f"checkpoint env key mismatch; missing={sorted(missing)}, unknown={sorted(unknown)}")
    if values["NODE_ENV"] not in {"development", "test"}:
        fail("NODE_ENV must be development or test")
    expected = {
        "PORT": "4001",
        "AUTH_DB_NAME": "fastapi_sso_dev",
        "AUTH_DB_USER": "fastapi_dev",
        "DATABASE_URL": "postgresql://fastapi_dev:synthetic-fastapi-db-only@postgres-fastapi-dev:5432/fastapi_sso_dev",
        "REDIS_URL": "redis://redis-fastapi-dev:6379/0",
        "JWT_ACCESS_ALGORITHM": "RS256",
    }
    for key, expected_value in expected.items():
        if values[key] != expected_value:
            fail(f"{key} must resolve to its isolated synthetic value")
    for key in SECRET_KEYS:
        value = values[key].lower()
        if value and not any(marker in value for marker in ("synthetic", "replace", "example")):
            fail(f"{key} must be empty or explicitly synthetic")
    if not values["JWT_ACCESS_KEY_ID"].startswith("synthetic-"):
        fail("JWT_ACCESS_KEY_ID must be explicitly synthetic")
    private_key_fingerprint = hashlib.sha256(
        values["JWT_ACCESS_PRIVATE_KEY"].encode("utf-8")
    ).hexdigest()
    if private_key_fingerprint != SYNTHETIC_PRIVATE_KEY_SHA256:
        fail("JWT_ACCESS_PRIVATE_KEY must match the pinned synthetic fixture")
    try:
        public_jwk = json.loads(values["JWT_ACCESS_PUBLIC_JWK"])
        clients = json.loads(values["AUTH_CLIENTS_JSON"])
    except json.JSONDecodeError as error:
        fail(f"JSON environment value is invalid: {error.msg}")
    if public_jwk.get("kid") != values["JWT_ACCESS_KEY_ID"]:
        fail("synthetic JWK kid must match JWT_ACCESS_KEY_ID")
    modulus = public_jwk.get("n")
    if (
        not isinstance(modulus, str)
        or hashlib.sha256(modulus.encode("ascii")).hexdigest() != SYNTHETIC_MODULUS_SHA256
        or public_jwk.get("e") != "AQAB"
    ):
        fail("JWT_ACCESS_PUBLIC_JWK must match the pinned synthetic RSA public key")
    if not isinstance(clients, list) or not clients:
        fail("AUTH_CLIENTS_JSON must contain at least one client")
    database = urlsplit(values["DATABASE_URL"])
    if database.hostname != "postgres-fastapi-dev" or database.port != 5432:
        fail("DATABASE_URL must target only postgres-fastapi-dev")
    serialized = "\n".join(values.values()).lower()
    forbidden_references = ("auth-server-app-1", "auth-postgres-data", "production")
    if any(item in serialized for item in forbidden_references):
        fail("current or production resource reference detected")
    return values


def normalized_manifest(compose: dict[str, Any]) -> dict[str, Any]:
    services: dict[str, Any] = {}
    for service_name, service in compose.get("services", {}).items():
        bindings = [
            f"{port.get('host_ip')}:{port.get('published')}:{port.get('target')}/{port.get('protocol')}"
            for port in service.get("ports", [])
        ]
        mounts = [
            {
                "source": mount.get("source"),
                "target": mount.get("target"),
                "type": mount.get("type"),
            }
            for mount in service.get("volumes", [])
        ]
        mounts.extend(
            {
                "source": None,
                "target": tmpfs.split(":", 1)[0],
                "type": "tmpfs",
            }
            for tmpfs in service.get("tmpfs", [])
        )
        services[service_name] = {
            "containerName": service.get("container_name"),
            "hostBindings": sorted(bindings),
            "mounts": sorted(mounts, key=lambda mount: str(mount["target"])),
            "networks": sorted(service.get("networks", {})),
        }
    return {
        "status": "PROVISIONAL",
        "project": compose.get("name"),
        "services": services,
        "networks": {key: value.get("name") for key, value in compose.get("networks", {}).items()},
        "volumes": {key: value.get("name") for key, value in compose.get("volumes", {}).items()},
    }


def validate_resolved(compose_path: Path, manifest_path: Path, env_path: Path) -> None:
    compose = json.loads(compose_path.read_text())
    expected = json.loads(manifest_path.read_text())
    actual = normalized_manifest(compose)
    if actual != expected:
        fail("resolved resources differ from manifest: " + json.dumps(actual, sort_keys=True))
    env = validate_env(env_path)
    app_env = compose["services"]["app-fastapi-dev"].get("environment", {})
    if app_env.get("NODE_ENV") != "development":
        fail("resolved app NODE_ENV must be development")
    for key in KNOWN_ENV_KEYS - {"NODE_ENV", "AUTH_DB_ADMIN_PASSWORD"}:
        if app_env.get(key) != env[key]:
            fail(f"resolved app environment differs for {key}")
    postgres_env = compose["services"]["postgres-fastapi-dev"].get("environment", {})
    if postgres_env != {
        "POSTGRES_DB": "fastapi_sso_dev",
        "POSTGRES_PASSWORD": "synthetic-fastapi-db-only",
        "POSTGRES_USER": "fastapi_dev",
    }:
        fail("resolved PostgreSQL environment is not exactly synthetic")


def _read_name_set(path: Path) -> set[str]:
    return {line for line in path.read_text().splitlines() if line}


def validate_runtime(
    inspect_path: Path,
    container_names_path: Path,
    network_names_path: Path,
    volume_names_path: Path,
    manifest_path: Path,
) -> None:
    containers = json.loads(inspect_path.read_text())
    expected = json.loads(manifest_path.read_text())
    by_name = {container["Name"].lstrip("/"): container for container in containers}
    expected_names = {service["containerName"] for service in expected["services"].values()}
    if set(by_name) != expected_names or _read_name_set(container_names_path) != expected_names:
        fail("runtime container names differ from manifest")
    if _read_name_set(network_names_path) != set(expected["networks"].values()):
        fail("runtime network names differ from manifest")
    if _read_name_set(volume_names_path) != set(expected["volumes"].values()):
        fail("runtime volume names differ from manifest")
    for service in expected["services"].values():
        container = by_name[service["containerName"]]
        bindings: list[str] = []
        for target, published in container["NetworkSettings"]["Ports"].items():
            target_port, protocol = target.split("/", 1)
            for binding in published or []:
                bindings.append(
                    f"{binding['HostIp']}:{binding['HostPort']}:{target_port}/{protocol}"
                )
        mounts = []
        for mount in container["Mounts"]:
            source = mount.get("Name") if mount["Type"] == "volume" else None
            mounts.append({"source": source, "target": mount["Destination"], "type": mount["Type"]})
        mounts.extend(
            {"source": None, "target": target, "type": "tmpfs"}
            for target in container["HostConfig"].get("Tmpfs", {})
        )
        expected_mounts = []
        for mount in service["mounts"]:
            source = mount["source"]
            if mount["type"] == "volume":
                source = expected["volumes"][source]
            expected_mounts.append(
                {"source": source, "target": mount["target"], "type": mount["type"]}
            )
        actual = {
            "hostBindings": sorted(bindings),
            "mounts": sorted(mounts, key=lambda item: str(item["target"])),
            "networks": sorted(container["NetworkSettings"]["Networks"]),
        }
        expected_runtime = {
            "hostBindings": sorted(service["hostBindings"]),
            "mounts": sorted(expected_mounts, key=lambda item: str(item["target"])),
            "networks": sorted(expected["networks"][name] for name in service["networks"]),
        }
        if actual != expected_runtime:
            fail(
                f"runtime resources differ for {service['containerName']}: "
                + json.dumps(actual, sort_keys=True)
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    env_parser = subparsers.add_parser("env")
    env_parser.add_argument("env_file", type=Path)
    resolved_parser = subparsers.add_parser("resolved")
    resolved_parser.add_argument("compose_json", type=Path)
    resolved_parser.add_argument("manifest", type=Path)
    resolved_parser.add_argument("env_file", type=Path)
    runtime_parser = subparsers.add_parser("runtime")
    runtime_parser.add_argument("inspect_json", type=Path)
    runtime_parser.add_argument("container_names", type=Path)
    runtime_parser.add_argument("network_names", type=Path)
    runtime_parser.add_argument("volume_names", type=Path)
    runtime_parser.add_argument("manifest", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.command == "env":
            validate_env(arguments.env_file)
        elif arguments.command == "resolved":
            validate_resolved(arguments.compose_json, arguments.manifest, arguments.env_file)
        else:
            validate_runtime(
                arguments.inspect_json,
                arguments.container_names,
                arguments.network_names,
                arguments.volume_names,
                arguments.manifest,
            )
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
