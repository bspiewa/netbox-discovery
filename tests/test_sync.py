from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from netbox_discovery.config import FortiGateDeviceSettings
from netbox_discovery.netbox_client import IpResult
from netbox_discovery.sources.fortigate import parse_system_status
from netbox_discovery.sources.nmap import Host
from netbox_discovery.sync import fortigate_device as fd
from netbox_discovery.sync.ip_sync import sync_networks
from tests.conftest import load_json, record

CFG = FortiGateDeviceSettings(site_slug="main-office")
IDENTITY = fd.Identity(
    hostname="fw-example", serial="FGT70GTK00000001", model="FortiGate 70G", version="v7.6.4"
)


# ---------------------------------------------------------------- ip_sync


def test_sync_networks_counts_and_errors(nb: MagicMock) -> None:
    def scanner(net: Any) -> list[Host]:
        if str(net) == "198.51.100.0/24":
            raise RuntimeError("nmap failed")
        return [Host("192.0.2.1"), Host("192.0.2.2"), Host("192.0.2.3")]

    nb.ipam.ip_addresses.filter.side_effect = lambda address: (
        [record(id=1)] if address == "192.0.2.1" else []
    )
    nb.extras.tags.get.return_value = record(id=1)
    nb.ipam.ip_addresses.create.side_effect = [None, RuntimeError("409")]
    report = sync_networks(
        nb,
        ["192.0.2.0/24", "198.51.100.0/24"],  # type: ignore[list-item]
        scanner,
        dry_run=False,
        tag="netbox-discovery",
        status="active",
        description="d",
    )
    assert report.counts[IpResult.EXISTS] == 1
    assert report.counts[IpResult.CREATED] == 1
    assert len(report.errors) == 2
    assert not report.ok
    assert "errors=2" in report.summary()


def test_sync_networks_dry_run_never_writes(nb: MagicMock) -> None:
    report = sync_networks(
        nb,
        ["192.0.2.0/24"],
        lambda n: [Host("192.0.2.9")],  # type: ignore[list-item]
        dry_run=True,
        tag="netbox-discovery",
        status="active",
        description="",
    )
    assert report.ok
    assert report.counts[IpResult.WOULD_CREATE] == 1
    nb.ipam.ip_addresses.create.assert_not_called()
    nb.extras.tags.create.assert_not_called()


# ---------------------------------------------------------------- fortigate_device


def test_slugify() -> None:
    assert fd.slugify("FortiGate 70G") == "fortigate-70g"


def _fg(payload: dict[str, Any]) -> MagicMock:
    fg = MagicMock()
    fg.get_system_status.return_value = parse_system_status(payload)
    return fg


def test_discover(caplog: pytest.LogCaptureFixture) -> None:
    identity = fd.discover(_fg(load_json("fortigate_status.json")))
    assert identity == IDENTITY
    assert "FGT70GTK00000001" not in caplog.text  # serial is masked in logs


@pytest.mark.parametrize("serial", ["Ukryty", "hidden", "UNKNOWN"])
def test_discover_placeholder_serial(serial: str) -> None:
    payload = load_json("fortigate_status.json") | {"serial": serial}
    with pytest.raises(fd.SyncError, match="placeholder"):
        fd.discover(_fg(payload))


def test_discover_missing_identity() -> None:
    with pytest.raises(fd.SyncError, match="identity"):
        fd.discover(_fg({"results": {}}))


@pytest.fixture
def nb_ready(nb: MagicMock) -> MagicMock:
    nb.dcim.sites.get.return_value = record(id=1, name="Main", slug="main-office")
    nb.dcim.manufacturers.get.return_value = record(id=2, name="Fortinet")
    return nb


def test_plan_create_with_missing_role_and_type(nb_ready: MagicMock) -> None:
    plan = fd.build_plan(nb_ready, IDENTITY, CFG)
    assert plan.action is fd.Action.CREATE
    assert plan.role is None and plan.device_type is None
    assert plan.device_type_slug == "fortigate-70g"
    nb_ready.dcim.devices.create.assert_not_called()
    fd.log_plan(plan, CFG)


def test_plan_type_override(nb_ready: MagicMock) -> None:
    cfg = CFG.model_copy(update={"device_type_model": "FG-70G", "device_type_slug": "fg70g"})
    plan = fd.build_plan(nb_ready, IDENTITY, cfg)
    assert (plan.device_type_model, plan.device_type_slug) == ("FG-70G", "fg70g")


def test_plan_existing_device(nb_ready: MagicMock, caplog: pytest.LogCaptureFixture) -> None:
    nb_ready.dcim.devices.filter.return_value = [record(id=9, name="old-name")]
    plan = fd.build_plan(nb_ready, IDENTITY, CFG)
    assert plan.action is fd.Action.EXISTS
    assert "differs" in caplog.text
    assert fd.apply_plan(nb_ready, plan, CFG, "t") is None
    fd.log_plan(plan, CFG)


def test_plan_disabled(nb_ready: MagicMock) -> None:
    plan = fd.build_plan(nb_ready, IDENTITY, CFG.model_copy(update={"create_device": False}))
    assert plan.action is fd.Action.DISABLED
    fd.log_plan(plan, CFG)


@pytest.mark.parametrize(
    ("setup", "message"),
    [
        (lambda nb: setattr(nb.dcim.sites.get, "return_value", None), "Site"),
        (lambda nb: setattr(nb.dcim.manufacturers.get, "return_value", None), "Manufacturer"),
        (
            lambda nb: setattr(
                nb.dcim.devices.filter, "return_value", [record(id=1), record(id=2)]
            ),
            "Multiple",
        ),
        (lambda nb: setattr(nb.dcim.devices.get, "return_value", record(id=3)), "already exists"),
        (
            lambda nb: setattr(
                nb.dcim.device_types.get, "return_value", record(id=4, manufacturer=record(id=99))
            ),
            "different manufacturer",
        ),
    ],
)
def test_plan_conflicts(nb_ready: MagicMock, setup: Any, message: str) -> None:
    setup(nb_ready)
    with pytest.raises(fd.SyncError, match=message):
        fd.build_plan(nb_ready, IDENTITY, CFG)


def test_plan_requires_site_slug(nb: MagicMock) -> None:
    with pytest.raises(fd.SyncError, match="site_slug"):
        fd.build_plan(nb, IDENTITY, FortiGateDeviceSettings())


def test_apply_creates_role_type_and_device(nb_ready: MagicMock) -> None:
    plan = fd.build_plan(nb_ready, IDENTITY, CFG)
    nb_ready.extras.tags.get.return_value = record(id=1)
    nb_ready.dcim.device_roles.create.return_value = record(id=10)
    nb_ready.dcim.device_roles.get.return_value = record(id=10)
    nb_ready.dcim.device_types.create.return_value = record(id=11)
    nb_ready.dcim.device_types.get.return_value = record(id=11)
    nb_ready.dcim.devices.create.return_value = record(id=12)
    nb_ready.dcim.devices.get.return_value = record(id=12, name="fw-example")

    device = fd.apply_plan(nb_ready, plan, CFG, "netbox-discovery")

    assert device.id == 12
    payload = nb_ready.dcim.devices.create.call_args.args[0]
    assert payload == {
        "name": "fw-example",
        "serial": "FGT70GTK00000001",
        "device_type": 11,
        "role": 10,
        "site": 1,
        "status": "active",
        "tags": [{"slug": "netbox-discovery"}],
    }


def test_apply_detects_name_mismatch(nb_ready: MagicMock) -> None:
    nb_ready.dcim.device_roles.get.return_value = record(id=10, name="Firewall")
    nb_ready.dcim.device_types.get.return_value = record(
        id=11, model="FortiGate 70G", manufacturer=record(id=2)
    )
    plan = fd.build_plan(nb_ready, IDENTITY, CFG)
    nb_ready.dcim.devices.create.return_value = record(id=12)
    nb_ready.dcim.devices.get.return_value = record(id=12, name="other")
    with pytest.raises(fd.SyncError, match="differs"):
        fd.apply_plan(nb_ready, plan, CFG, None)
    nb_ready.dcim.device_roles.create.assert_not_called()
