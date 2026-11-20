from __future__ import annotations

import subprocess
from typing import Any

import pytest

from netbox_discovery.sources.nmap import NmapError, build_command, parse_xml, scan_network
from tests.conftest import load_fixture


def test_build_command_puts_target_after_separator() -> None:
    assert build_command("192.0.2.0/24") == ["nmap", "-sn", "-oX", "-", "--", "192.0.2.0/24"]
    assert build_command("2001:db8::/120")[-3:] == ["-6", "--", "2001:db8::/120"]


@pytest.mark.parametrize("bad", ["-iL /etc/passwd", "192.0.2.0/24 --script x", "example.com"])
def test_build_command_rejects_non_networks(bad: str) -> None:
    with pytest.raises(ValueError):
        build_command(bad)


def test_parse_xml() -> None:
    hosts = parse_xml(load_fixture("nmap_sample.xml"))
    assert [h.ip for h in hosts] == ["192.0.2.1", "192.0.2.10"]
    assert hosts[0].mac == "00:11:22:aa:bb:cc"
    assert hosts[0].vendor == "Fortinet"
    assert hosts[0].hostname == "fw.example.com"
    assert hosts[1].mac is None and hosts[1].hostname is None


def test_parse_xml_invalid() -> None:
    with pytest.raises(NmapError):
        parse_xml("<not xml")


def _runner(returncode: int = 0, stdout: str = "", stderr: str = "") -> Any:
    calls: list[list[str]] = []

    def run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)

    run.calls = calls  # type: ignore[attr-defined]
    return run


def test_scan_network_uses_runner() -> None:
    runner = _runner(stdout=load_fixture("nmap_sample.xml"))
    hosts = scan_network("192.0.2.0/24", runner=runner)
    assert len(hosts) == 2
    assert runner.calls == [["nmap", "-sn", "-oX", "-", "--", "192.0.2.0/24"]]


def test_scan_network_error() -> None:
    with pytest.raises(NmapError, match="exited with 1"):
        scan_network("192.0.2.0/24", runner=_runner(returncode=1, stderr="boom"))


def test_scan_network_timeout() -> None:
    def run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd, 1)

    with pytest.raises(NmapError, match="timed out"):
        scan_network("192.0.2.0/24", runner=run)
