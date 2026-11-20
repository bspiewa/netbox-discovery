from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


def load_json(name: str) -> Any:
    return json.loads(load_fixture(name))


def record(**kwargs: Any) -> SimpleNamespace:
    """Stand-in for a pynetbox Record."""
    return SimpleNamespace(**kwargs)


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make sure no real tokens/config from the developer environment leak into tests."""
    for key in list(os.environ):
        if key.startswith("NBD_") or key in ("NETBOX_TOKEN", "FORTIGATE_TOKEN"):
            monkeypatch.delenv(key, raising=False)


@pytest.fixture
def nb() -> MagicMock:
    """Mocked pynetbox API: every endpoint returns 'not found' by default."""
    api = MagicMock()
    for endpoint in (
        api.ipam.ip_addresses,
        api.ipam.prefixes,
        api.extras.tags,
        api.dcim.sites,
        api.dcim.manufacturers,
        api.dcim.device_roles,
        api.dcim.device_types,
        api.dcim.devices,
    ):
        endpoint.get.return_value = None
        endpoint.filter.return_value = []
    return api


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(
        """
netbox:
  url: "https://netbox.example.com"
discovery:
  networks: ["192.0.2.0/24"]
fortigate:
  enabled: true
  url: "https://198.51.100.1:4443"
fortigate_device:
  site_slug: "main-office"
"""
    )
    return path
