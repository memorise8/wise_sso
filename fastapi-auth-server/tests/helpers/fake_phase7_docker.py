#!/usr/bin/python3
from pathlib import Path

Path(__file__).with_name("docker-invoked").write_text("invoked\n", encoding="utf-8")
raise SystemExit(99)
