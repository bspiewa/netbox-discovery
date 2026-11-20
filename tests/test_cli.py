from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from netbox_discovery import cli
from netbox_discovery.config import load_settings
from netbox_discovery.sources.fortigate import (
    parse_dhcp_leases,
    parse_dhcp_servers,
    parse_interface_status,
    parse_interfaces,
    parse_system_status,
)
from netbox_discovery.sources.nmap import Host
from tests.conftest import load_json, record
from tests.fake_netbox import FakeNetBox


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NBD_NETBOX__TOKEN", "nb-token")
    monkeypatch.setenv("NBD_FORTIGATE__TOKEN", "fg-token")


def run(config_file: Path, *args: str) -> int:
    return cli.main(["-c", str(config_file), "--env-file", "", *args])


def test_config_error_exit_code(tmp_path: Path) -> None:
    assert run(tmp_path / "missing.yaml", "scan") == cli.EXIT_CONFIG


def test_missing_token_exit_code(config_file: Path) -> None:
    assert run(config_file, "scan") == cli.EXIT_CONFIG


def test_scan_dry_run(
    config_file: Path, env: None, nb: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "build_api", lambda s: nb)
    monkeypatch.setattr(cli, "scan_network", lambda net, timeout: [Host("192.0.2.1")])
    assert run(config_file, "scan") == cli.EXIT_OK
    nb.ipam.ip_addresses.create.assert_not_called()


def test_scan_apply(
    config_file: Path, env: None, nb: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "build_api", lambda s: nb)
    monkeypatch.setattr(cli, "scan_network", lambda net, timeout: [Host("192.0.2.1")])
    nb.extras.tags.get.return_value = record(id=1)
    assert run(config_file, "scan", "--apply") == cli.EXIT_OK
    nb.ipam.ip_addresses.create.assert_called_once()


def _fake_fg(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    fg = MagicMock()
    fg.get_system_status.return_value = parse_system_status(load_json("fortigate_status.json"))
    fg.get_dhcp_leases.return_value = parse_dhcp_leases(load_json("fortigate_dhcp_leases.json"))
    fg.get_dhcp_servers.return_value = parse_dhcp_servers(load_json("fortigate_dhcp_servers.json"))
    monkeypatch.setattr(cli, "FortiGateClient", lambda **kw: fg)
    return fg


def test_fortigate_device_dry_run(
    config_file: Path, env: None, nb: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_fg(monkeypatch)
    monkeypatch.setattr(cli, "build_api", lambda s: nb)
    nb.dcim.sites.get.return_value = record(id=1, name="Main", slug="main-office")
    nb.dcim.manufacturers.get.return_value = record(id=2, name="Fortinet")
    assert run(config_file, "fortigate-device") == cli.EXIT_OK
    nb.dcim.devices.create.assert_not_called()


def test_fortigate_device_sync_error(
    config_file: Path, env: None, nb: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_fg(monkeypatch)
    monkeypatch.setattr(cli, "build_api", lambda s: nb)
    assert run(config_file, "fortigate-device", "--apply") == cli.EXIT_ERROR  # site missing


def test_fortigate_reports(
    config_file: Path,
    env: None,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _fake_fg(monkeypatch)
    assert run(config_file, "fortigate-status") == cli.EXIT_OK
    assert run(config_file, "fortigate-dhcp-report", "--limit", "1") == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "FortiGate 70G" in out
    assert "FGT70GTK00000001" not in out
    assert "DHCP leases: 2" in out


def test_fortigate_disabled(config_file: Path, env: None) -> None:
    config_file.write_text(config_file.read_text().replace("enabled: true", "enabled: false"))
    assert run(config_file, "fortigate-status") == cli.EXIT_CONFIG


def _fake_fg_network(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    fg = _fake_fg(monkeypatch)
    fg.get_interfaces.return_value = parse_interfaces(load_json("fortigate_interfaces.json"))
    fg.get_interface_status.return_value = parse_interface_status(
        load_json("fortigate_interface_status.json")
    )
    return fg


def test_fortigate_network_requires_device(
    config_file: Path, env: None, nb: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_fg_network(monkeypatch)
    monkeypatch.setattr(cli, "build_api", lambda s: nb)
    assert run(config_file, "fortigate-network") == cli.EXIT_ERROR


def test_fortigate_network_dry_run(
    config_file: Path, env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeNetBox()
    site = fake.dcim.sites.add(name="Main", slug="main-office")
    fake.dcim.devices.add(name="fw-example", serial="FGT70GTK00000001", site=site)
    _fake_fg_network(monkeypatch)
    monkeypatch.setattr(cli, "build_api", lambda s: fake)
    assert run(config_file, "fortigate-network") == cli.EXIT_OK
    assert fake.total_created() == 0


def test_management_ip(config_file: Path) -> None:
    assert cli._management_ip(load_settings(config_file, env_file=None)) == "198.51.100.1"
