import json
import os
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
EVENTS = Path(__file__).resolve().parent / "events"


@pytest.fixture(autouse=True)
def offline_aws_env(monkeypatch):
    """Make sure no test can reach real AWS: fake credentials, no IMDS, no profile."""
    for key in list(os.environ):
        if key.startswith("AWS_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")


def load_event(name: str) -> dict:
    return json.loads((EVENTS / f"{name}.json").read_text(encoding="utf-8"))
