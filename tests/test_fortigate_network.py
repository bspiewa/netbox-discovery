from __future__ import annotations

from typing import Any

import pytest

from netbox_discovery.config import FortiGateNetworkSettings
from netbox_discovery.sources.fortigate import (
    parse_dhcp_leases,
    parse_dhcp_servers,
    parse_interface_status,
    parse_interfaces,
    parse_ip_mask,
    parse_system_status,
)
from netbox_discovery.sync import fortigate_network as fn
from tests.conftest import load_json
from tests.fake_netbox import FakeNetBox, FakeRecord

TAG = "netbox-discovery"


def network_data() -> fn.NetworkData:
    return fn.NetworkData(
        status=parse_system_status(load_json("fortigate_status.json")),
        interfaces=parse_interfaces(load_json("fortigate_interfaces.json")),
        interface_status=parse_interface_status(load_json("fortigate_interface_status.json")),
        dhcp_servers=parse_dhcp_servers(load_json("fortigate_network_dhcp_servers.json")),
        dhcp_leases=parse_dhcp_leases(load_json("fortigate_network_dhcp_leases.json")),
    )


@pytest.fixture
def fake() -> tuple[FakeNetBox, FakeRecord, FakeRecord]:
    nb = FakeNetBox()
    site = nb.dcim.sites.add(name="Main Office", slug="main-office")
    manufacturer = FakeRecord(nb.dcim.devices, 7, {"name": "Fortinet"})
    device = nb.dcim.devices.add(
        name="fw-example",
        serial="FGT70GTK00000001",
        site=site,
        device_type=FakeRecord(nb.dcim.devices, 8, {"manufacturer": manufacturer}),
    )
    return nb, device, site


def run(fake: tuple[FakeNetBox, FakeRecord, FakeRecord], dry_run: bool, **cfg: Any) -> fn.Report:
    nb, device, site = fake
    return fn.NetworkSync(
        nb,
        network_data(),
        device,
        site,
        FortiGateNetworkSettings(**cfg),
        tag=TAG,
        dry_run=dry_run,
        management_ip="192.0.2.1",
    ).run()


# ------------------------------------------------------------------ parsing


def test_parse_ip_mask() -> None:
    assert str(parse_ip_mask("192.0.2.1 255.255.255.128")) == "192.0.2.1/25"
    assert parse_ip_mask("0.0.0.0 0.0.0.0") is None
    assert parse_ip_mask("") is None
    assert parse_ip_mask("garbage") is None


def test_parse_interfaces() -> None:
    by_name = {i.name: i for i in parse_interfaces(load_json("fortigate_interfaces.json"))}
    wan = by_name["wan1"]
    assert str(wan.ip) == "203.0.113.2/29"
    assert [str(s) for s in wan.secondary_ips] == ["203.0.113.3/29", "203.0.113.4/29"]
    assert by_name["fsw"].members == ("port1", "port2")
    assert by_name["VLAN100"].vlan_id == 100
    assert by_name["VLAN100"].parent == "fsw"
    assert by_name["port1"].vlan_id is None
    assert by_name["ssidtest"].enabled is False
    assert by_name["VLAN100"].mac is None  # 00:00:.. means "not set"


def test_parse_interface_status() -> None:
    status = parse_interface_status(load_json("fortigate_interface_status.json"))
    assert status["wan1"].mac == "00:11:22:33:44:01"
    assert status["wan1"].speed_mbps == 1000
    assert status["wan1"].duplex == "full"
    assert status["ssidtest"].mac is None
    assert status["ssidtest"].duplex == "half"


def test_parse_dhcp_server_extras() -> None:
    server = parse_dhcp_servers(load_json("fortigate_network_dhcp_servers.json"))[0]
    assert server.dns_servers == ("192.0.2.53",)
    assert server.domain == "example.com"
    assert server.lease_time == 604800
    assert parse_dhcp_servers(load_json("fortigate_network_dhcp_servers.json"))[1].enabled is False


# ------------------------------------------------------------------ helpers


def test_interface_type() -> None:
    cfg = FortiGateNetworkSettings(interface_type_overrides={"wan1": "10gbase-x-sfpp"})
    ifaces = {i.name: i for i in network_data().interfaces}
    assert fn.interface_type(ifaces["port1"], cfg) == "1000base-t"
    assert fn.interface_type(ifaces["wan1"], cfg) == "10gbase-x-sfpp"
    assert fn.interface_type(ifaces["fsw"], cfg) == "lag"
    assert fn.interface_type(ifaces["VLAN100"], cfg) == "virtual"
    assert fn.interface_type(ifaces["ssidtest"], cfg) == "virtual"


def test_dependency_order() -> None:
    order = [i.name for i in fn.dependency_order(network_data().interfaces)]
    assert order.index("fsw") < order.index("port1")
    assert order.index("fsw") < order.index("VLAN100")
    assert order.index("wan1") < order.index("vpn1")
    assert order.index("ssidtest") < order.index("wqtn.15.ssidtes")


def test_dns_name() -> None:
    assert fn.dns_name("Laptop 1") == "Laptop-1"
    assert fn.dns_name("łódź_pc.local.") == "d-_pc.local"
    assert fn.dns_name(None) == ""


# ------------------------------------------------------------------ sync


def test_dry_run_writes_nothing(fake: Any) -> None:
    report = run(fake, dry_run=True)
    nb = fake[0]
    assert report.ok
    assert nb.total_created() == 0
    assert nb.total_updates() == 0
    counts = report.counts
    # 11 interfaces minus ssl.root and wqtn.* (excluded by default)
    assert counts[("interface", "would_create")] == 9
    assert counts[("vlan", "would_create")] == 3
    assert counts[("prefix", "would_create")] == 5  # /29 counted once despite secondaries
    assert counts[("device", "would_update")] == 2  # platform + primary_ip4
    assert any("would_create" in line for line in report.lines())


def test_apply_creates_everything(fake: Any) -> None:
    nb, device, _site = fake
    report = run(fake, dry_run=False, dhcp_lease_interfaces=["VLAN101"])
    assert report.ok, report.errors

    ifaces = {r.name: r for r in nb.dcim.interfaces.records}
    vlans = {r.vid: r for r in nb.ipam.vlans.records}
    assert set(ifaces) == {
        "wan1",
        "port1",
        "port2",
        "fsw",
        "VLAN100",
        "VLAN101",
        "quarantine",
        "ssidtest",
        "vpn1",
    }
    assert ifaces["port1"].lag == ifaces["fsw"].id
    assert ifaces["port1"].speed == 1_000_000 and ifaces["port1"].duplex == "full"
    assert ifaces["VLAN100"].parent == ifaces["fsw"].id
    assert ifaces["VLAN100"].mode == "access" and ifaces["VLAN100"].untagged_vlan == vlans[100].id
    assert ifaces["fsw"].mode == "tagged"
    assert sorted(ifaces["fsw"].tagged_vlans) == sorted(v.id for v in vlans.values())
    assert ifaces["vpn1"].parent == ifaces["wan1"].id
    assert ifaces["ssidtest"].enabled is False and ifaces["ssidtest"].duplex is None
    assert ifaces["wan1"].primary_mac_address is not None
    assert all(c["tags"] == [{"slug": TAG}] for c in nb.dcim.interfaces.created)

    assert nb.ipam.vlan_groups.records[0].scope_type == "dcim.site"
    assert vlans[100].description == "MGMT"

    ips = {r.address: r for r in nb.ipam.ip_addresses.records}
    assert ips["192.0.2.1/25"].assigned_object_id == ifaces["VLAN100"].id
    assert ips["203.0.113.3/29"].role == "secondary"
    assert ips["192.0.2.140/25"].status == "reserved"
    assert ips["192.0.2.151/25"].status == "dhcp"
    assert ips["192.0.2.151/25"].dns_name == "Laptop-1"
    assert "192.0.2.5/25" not in ips  # VLAN100 leases not opted in
    assert device.primary_ip4 == ips["192.0.2.1/25"].id
    assert device.platform == nb.dcim.platforms.records[0].id

    ranges = nb.ipam.ip_ranges.records
    assert [(r.start_address, r.end_address) for r in ranges] == [
        ("192.0.2.150/25", "192.0.2.200/25")
    ]  # disabled server and excluded interface skipped
    assert "192.0.2.53" in ranges[0].description

    prefixes = {r.prefix: r for r in nb.ipam.prefixes.records}
    assert prefixes["192.0.2.0/25"].vlan == vlans[100].id
    assert "203.0.113.0/29" in prefixes


def test_second_run_is_idempotent(fake: Any) -> None:
    nb = fake[0]
    run(fake, dry_run=False, dhcp_lease_interfaces=["VLAN101"])
    created, updates = nb.total_created(), nb.total_updates()
    report = run(fake, dry_run=False, dhcp_lease_interfaces=["VLAN101"])
    assert report.ok
    assert nb.total_created() == created
    assert nb.total_updates() == updates
    assert all(action == "exists" for (_kind, action) in report.counts)


def test_existing_objects_only_empty_fields_filled(fake: Any) -> None:
    nb, device, _ = fake
    platform = nb.dcim.platforms.add(slug="manual", name="Manual")
    device.platform = platform.id
    prefix = nb.ipam.prefixes.add(prefix="192.0.2.0/25", description="hand-written", vrf=None)
    foreign = nb.dcim.interfaces.add(name="other", device=999)
    nb.ipam.ip_addresses.add(address="192.0.2.129/25", assigned_object_id=foreign.id)

    report = run(fake, dry_run=False)

    assert device.platform == platform.id  # not overwritten
    assert prefix.description == "hand-written"
    assert prefix.vlan is not None and prefix.scope_type == "dcim.site"  # empty fields filled
    assert report.counts[("ip_address", "conflict")] == 1


def test_duplicate_vlan_id_skipped(fake: Any) -> None:
    report = run(fake, dry_run=False, exclude_interfaces=[r"^ssl\."])
    assert report.counts[("vlan", "skipped_duplicate")] == 1
    assert sorted(v.vid for v in fake[0].ipam.vlans.records) == [100, 101, 4093]


def test_firmware_custom_field_and_journal(fake: Any) -> None:
    nb, device, _ = fake
    device.custom_fields = {"firmware_version": "v7.4.0"}
    run(fake, dry_run=False)
    assert device.custom_fields["firmware_version"] == "v7.6.4"
    assert "v7.4.0 -> v7.6.4" in nb.extras.journal_entries.created[0]["comments"]


def test_feature_toggles(fake: Any) -> None:
    nb = fake[0]
    run(
        fake,
        dry_run=False,
        sync_platform=False,
        sync_dhcp_ranges=False,
        sync_dhcp_reservations=False,
        sync_interface_ips=False,
    )
    assert not nb.dcim.platforms.records
    assert not nb.ipam.ip_ranges.records
    assert not nb.ipam.ip_addresses.records
    assert nb.ipam.prefixes.records  # prefixes still synced


def test_step_errors_are_collected(fake: Any) -> None:
    nb = fake[0]

    def boom(data: dict[str, Any]) -> None:
        raise RuntimeError("denied")

    nb.ipam.vlan_groups.create = boom  # type: ignore[method-assign]
    report = run(fake, dry_run=False)
    assert not report.ok
    assert "vlans" in report.errors[0]
    assert nb.dcim.interfaces.records  # other steps still ran


def test_apply_creates_missing_tag_first(fake: Any) -> None:
    """Regression: objects reference the tag, so it must exist before anything else (HTTP 400)."""
    nb = fake[0]
    assert not nb.extras.tags.records
    report = run(fake, dry_run=False)
    assert report.ok, report.errors
    assert [t.slug for t in nb.extras.tags.records] == [TAG]
    assert nb.dcim.interfaces.records


def test_tag_failure_aborts_run(fake: Any) -> None:
    nb = fake[0]

    def boom(data: dict[str, Any]) -> None:
        raise RuntimeError("403 Forbidden")

    nb.extras.tags.create = boom  # type: ignore[method-assign]
    report = run(fake, dry_run=False)
    assert not report.ok
    assert "tag" in report.errors[0]
    assert nb.total_created() == 0
    assert nb.total_updates() == 0
