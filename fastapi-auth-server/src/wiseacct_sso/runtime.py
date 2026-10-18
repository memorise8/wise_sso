"""Production entrypoint with a connection-free, secret-safe configuration check."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

import uvicorn
from pydantic import ValidationError

from wiseacct_sso.config import Settings, get_settings


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "serve"))
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args(argv)
    try:
        settings = get_settings()
    except ValidationError as error:
        # Never print the exception, input values, nested user-defined keys or ctx:
        # Settings validation errors can contain private keys and entire env values.
        known_fields = {
            field.validation_alias
            for field in Settings.model_fields.values()
            if isinstance(field.validation_alias, str)
        }
        fields = sorted(
            {
                str(item["loc"][0])
                for item in error.errors(include_input=False, include_context=False)
                if item["loc"] and item["loc"][0] in known_fields
            }
        )
        print(json.dumps({"status": "INVALID_CONFIG", "fields": fields}))
        return 2
    except Exception:
        print(json.dumps({"status": "INVALID_CONFIG"}))
        return 2

    if settings.node_env != "production":
        print(json.dumps({"status": "PRODUCTION_ENV_REQUIRED"}))
        return 2
    if args.action == "check":
        print(
            json.dumps(
                {
                    "status": "CONFIG_VALID",
                    "runtimeVerified": False,
                    "replacementReady": False,
                }
            )
        )
        return 0

    # Proxy handling belongs to the application's explicit trusted-proxy policy,
    # not ambient FORWARDED_ALLOW_IPS or Uvicorn's implicit loopback trust.
    uvicorn.run(
        "wiseacct_sso.main:create_runtime_app",
        factory=True,
        host=args.host,
        port=settings.port,
        proxy_headers=False,
        server_header=False,
        access_log=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
