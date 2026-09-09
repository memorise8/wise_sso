#!/usr/bin/env python3
"""Disposable child that exercises the actual A04 Python provider transport."""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[2]
TRANSPORT_PATH = ROOT / "contracts" / "bin" / "provider_transport.py"
SPEC = importlib.util.spec_from_file_location(
    "oauth_google_probe_transport", TRANSPORT_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("provider transport could not be loaded")
transport = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = transport
SPEC.loader.exec_module(transport)


async def _exercise(config_path: Path) -> None:
    scenarios = transport.load_scenarios(config_path)
    scenario = scenarios[0]
    recorder = transport.PrivateProviderRecordWriter.from_environment()
    if recorder is None:
        raise RuntimeError("private provider recorder is required")
    provider_transport = transport.TestOnlyProviderTransport(
        scenarios, recorder=recorder
    )
    async with httpx.AsyncClient(transport=provider_transport) as client:
        token = await client.post(
            transport.ENDPOINTS[scenario.provider].token,
            data={
                "grant_type": "authorization_code",
                "client_id": scenario.client_id,
                "client_secret": scenario.client_secret,
                "redirect_uri": scenario.redirect_uri,
                "code": scenario.code,
            },
        )
        token.raise_for_status()
        access_token = token.json()["access_token"]
        profile = await client.get(
            transport.ENDPOINTS[scenario.provider].user_info,
            headers={"authorization": f"Bearer {access_token}"},
        )
        profile.raise_for_status()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=("producer", "consumer"), required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--provider-config", type=Path, required=True)
    args = parser.parse_args()
    exercised = False

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *values: object) -> None:
            return

        def send_json(self, status: int, value: Any) -> None:
            raw = json.dumps(value, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            nonlocal exercised
            if self.path == "/health":
                self.send_json(200, {"status": "ready", "pid": os.getpid()})
                return
            if self.path == "/trigger" and args.role == "producer" and not exercised:
                exercised = True
                try:
                    asyncio.run(_exercise(args.provider_config))
                except Exception as exc:  # noqa: BLE001 - child exits on any probe failure
                    self.send_json(500, {"error": type(exc).__name__})
                    return
                self.send_json(200, {"status": "recorded"})
                return
            self.send_json(404, {})

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
