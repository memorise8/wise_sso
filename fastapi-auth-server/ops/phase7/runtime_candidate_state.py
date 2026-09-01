#!/usr/bin/env python3
"""Inspect only the fixed guarded candidate resources with tri-state results."""

from __future__ import annotations

import argparse
import subprocess

PROJECT = "wiseacct-sso-fastapi-dev"
REDIS_CONTAINER = "wiseacct-sso-fastapi-dev-redis"


def docker(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed Docker argv, guarded exact project
        ["docker", *arguments],  # noqa: S607 - PATH is intentionally test-overridable
        check=False,
        capture_output=True,
        text=True,
    )


def resources() -> int:
    commands = (
        (
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={PROJECT}",
            "--format",
            "{{.Names}}",
        ),
        (
            "network",
            "ls",
            "--filter",
            f"label=com.docker.compose.project={PROJECT}",
            "--format",
            "{{.Name}}",
        ),
        (
            "volume",
            "ls",
            "--filter",
            f"label=com.docker.compose.project={PROJECT}",
            "--format",
            "{{.Name}}",
        ),
    )
    present = False
    for arguments in commands:
        result = docker(*arguments)
        if result.returncode != 0:
            print("ERROR")
            return 2
        present = present or bool(result.stdout.strip())
    print("PRESENT" if present else "EMPTY")
    return 1 if present else 0


def redis_usable() -> int:
    listed = docker(
        "ps",
        "-a",
        "--filter",
        f"label=com.docker.compose.project={PROJECT}",
        "--filter",
        f"name=^/{REDIS_CONTAINER}$",
        "--format",
        "{{.Names}}",
    )
    if listed.returncode != 0:
        print("ERROR")
        return 2
    names = listed.stdout.splitlines()
    if not names:
        print("ABSENT")
        return 1
    if names != [REDIS_CONTAINER]:
        print("ERROR")
        return 2
    inspected = docker(
        "inspect",
        "--format",
        '{{.Name}}|{{.State.Running}}|{{index .Config.Labels "com.docker.compose.project"}}',
        REDIS_CONTAINER,
    )
    if inspected.returncode != 0:
        print("ERROR")
        return 2
    if inspected.stdout.strip() != f"/{REDIS_CONTAINER}|true|{PROJECT}":
        print("UNUSABLE")
        return 1
    ping = docker("exec", REDIS_CONTAINER, "redis-cli", "PING")
    if ping.returncode != 0:
        print("ERROR")
        return 2
    if ping.stdout.strip() != "PONG":
        print("UNUSABLE")
        return 1
    print("USABLE")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("resources", "redis-usable"))
    args = parser.parse_args()
    return resources() if args.mode == "resources" else redis_usable()


if __name__ == "__main__":
    raise SystemExit(main())
