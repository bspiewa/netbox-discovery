from __future__ import annotations

import pytest
import responses

from netbox_discovery.sources.fortigate import (
    FortiGateClient,
    FortiGateError,
    parse_dhcp_leases,
    parse_dhcp_servers,
    parse_system_status,
)
from tests.conftest import load_json

BASE = "https://198.51.100.1:4443"


def test_parse_system_status() -> None:
    s = parse_system_status(load_json("fortigate_status.json"))
    assert s.hostname == "fw-example"
    assert s.serial == "FGT70GTK00000001"
    assert s.display_model == "FortiGate 70G"
    assert s.version == "v7.6.4"
    assert s.build == 3596


def test_display_model_fallback() -> None:
    s = parse_system_status({"results": {"model": "FGT70G"}})
    assert s.display_model == "FGT70G"


def test_parse_dhcp_leases() -> None:
    leases = parse_dhcp_leases(load_json("fortigate_dhcp_leases.json"))
    assert leases[0].mac == "aa:bb:cc:00:00:01"
    assert leases[0].expires_at == "2027-01-15T08:00:00+00:00"
    assert leases[0].dhcp_server_id == 1
    assert leases[1].mac == ""  # null MAC handled
    assert leases[1].expires_at is None
    assert leases[1].reserved is False


def test_parse_dhcp_servers() -> None:
    servers = parse_dhcp_servers(load_json("fortigate_dhcp_servers.json"))
    assert servers[0].gateway == "192.0.2.1"
    assert len(servers[0].reserved_addresses) == 1


def test_client_requires_token() -> None:
    with pytest.raises(ValueError):
        FortiGateClient(BASE, "")


def test_repr_hides_token() -> None:
    assert "s3cr3t" not in repr(FortiGateClient(BASE, "s3cr3t"))


@responses.activate
def test_get_sends_bearer_and_vdom() -> None:
    responses.get(f"{BASE}/api/v2/monitor/system/status", json=load_json("fortigate_status.json"))
    fg = FortiGateClient(BASE + "/", "tok", vdom="root")
    assert fg.get_system_status().hostname == "fw-example"
    req = responses.calls[0].request
    assert req.headers["Authorization"] == "Bearer tok"
    assert "vdom=root" in (req.url or "")


@responses.activate
def test_get_dhcp() -> None:
    responses.get(
        f"{BASE}/api/v2/monitor/system/dhcp", json=load_json("fortigate_dhcp_leases.json")
    )
    responses.get(
        f"{BASE}/api/v2/cmdb/system.dhcp/server", json=load_json("fortigate_dhcp_servers.json")
    )
    responses.get(f"{BASE}/api/v2/cmdb/system/interface", json={"results": [{"name": "wan1"}]})
    fg = FortiGateClient(BASE, "tok")
    assert len(fg.get_dhcp_leases()) == 2
    assert len(fg.get_dhcp_servers()) == 1
    assert fg.get_interfaces() == [{"name": "wan1"}]


@responses.activate
def test_auth_error() -> None:
    responses.get(f"{BASE}/api/v2/monitor/system/status", status=401)
    with pytest.raises(FortiGateError, match="rejected the API token"):
        FortiGateClient(BASE, "bad").get_system_status()


@responses.activate
def test_api_status_error() -> None:
    responses.get(f"{BASE}/api/v2/monitor/system/status", json={"status": "error"})
    with pytest.raises(FortiGateError, match="API error"):
        FortiGateClient(BASE, "tok").get_system_status()
