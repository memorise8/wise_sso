from pathlib import Path

import pytest

from wiseacct_sso.config import Settings

ROOT = Path(__file__).parents[1]


@pytest.fixture
def synthetic_settings() -> Settings:
    return Settings(_env_file=ROOT / ".env.example")  # type: ignore[call-arg]
