"""FortiGate interfaces, VLANs, prefixes, interface IPs and DHCP data -> NetBox.

Policy (same as the rest of the tool):
  * missing objects are created and tagged with ``sync.tag``;
  * existing objects are never overwritten - only *empty* fields are filled in;
  * in dry-run nothing is written; placeholders stand in for objects that would be created,
    so the whole run (and its report) can still be simulated.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from ipaddress import IPv4Interface, IPv6Interface, ip_address, ip_interface
from types import SimpleNamespace
from typing import Any

from netbox_discovery.config import FortiGateNetworkSettings
from netbox_discovery.netbox_client import NetBoxError, describe_api_error, ensure_tag, tag_ref
from netbox_discovery.sources.fortigate import (
    DhcpLease,
    DhcpServer,
    FortiGateClient,
    Interface,
    InterfaceStatus,
    SystemStatus,
)

log = logging.getLogger(__name__)

IFACE_TYPE_MAP = {
    "aggregate": "lag",
    "redundant": "lag",
    "switch": "bridge",
    "hard-switch": "bridge",
    "vlan": "virtual",
    "tunnel": "virtual",
    "loopback": "virtual",
    "vap-switch": "virtual",
    "emac-vlan": "virtual",
    "vxlan": "virtual",
    "geneve": "virtual",
    "ssl": "virtual",
}
DNS_NAME_INVALID = re.compile(r"[^0-9A-Za-z*._-]")
LABEL_MAX = 64
DESCRIPTION_MAX = 200


@dataclass
class NetworkData:
    """Everything read from FortiGate for one run."""

    status: SystemStatus
    interfaces: list[Interface]
    interface_status: dict[str, InterfaceStatus]
    dhcp_servers: list[DhcpServer]
    dhcp_leases: list[DhcpLease]


def discover(fg: FortiGateClient, with_leases: bool) -> NetworkData:
    return NetworkData(
        status=fg.get_system_status(),
        interfaces=fg.get_interfaces(),
        interface_status=fg.get_interface_status(),
        dhcp_servers=fg.get_dhcp_servers(),
        dhcp_leases=fg.get_dhcp_leases() if with_leases else [],
    )


@dataclass
class Report:
    counts: Counter[tuple[str, str]] = field(default_factory=Counter)
    errors: list[str] = field(default_factory=list)

    def add(self, kind: str, action: str) -> None:
        self.counts[(kind, action)] += 1

    @property
    def ok(self) -> bool:
        return not self.errors

    def lines(self) -> list[str]:
        kinds: dict[str, list[str]] = {}
        for (kind, action), n in sorted(self.counts.items()):
            kinds.setdefault(kind, []).append(f"{action}={n}")
        return [f"{kind}: {', '.join(parts)}" for kind, parts in kinds.items()]


def interface_type(iface: Interface, cfg: FortiGateNetworkSettings) -> str:
    if iface.name in cfg.interface_type_overrides:
        return cfg.interface_type_overrides[iface.name]
    if iface.type == "physical":
        return cfg.physical_interface_type
    return IFACE_TYPE_MAP.get(iface.type, "other")


def dns_name(hostname: str | None) -> str:
    return DNS_NAME_INVALID.sub("-", hostname or "").strip("-.")[:255]


def dependency_order(interfaces: list[Interface]) -> list[Interface]:
    """Order interfaces so that parents, LAGs and bridges are created before their users."""
    by_name = {i.name: i for i in interfaces}
    deps: dict[str, set[str]] = {i.name: set() for i in interfaces}
    for i in interfaces:
        if i.parent in by_name:
            deps[i.name].add(i.parent)
        for member in i.members:
            if member in deps:
                deps[member].add(i.name)
    ordered: list[Interface] = []
    done: set[str] = set()
    while len(done) < len(interfaces):
        ready = [n for n in deps if n not in done and deps[n] <= done]
        if not ready:  # cycle - should not happen, append the rest as-is
            ready = [n for n in deps if n not in done]
        for name in sorted(ready):
            ordered.append(by_name[name])
            done.add(name)
    return ordered


def _is_empty(value: Any) -> bool:
    return value is None or value in ("", [], {})


class _Planned:
    """ID of an object that would be created (dry-run)."""

    def __repr__(self) -> str:
        return "<planned>"


PLANNED: Any = _Planned()


def _real(record: Any) -> bool:
    """True if ``record`` exists in NetBox (has an integer ID)."""
    return isinstance(getattr(record, "id", None), int)


class NetworkSync:
    def __init__(
        self,
        nb: Any,
        data: NetworkData,
        device: Any,
        site: Any,
        cfg: FortiGateNetworkSettings,
        *,
        tag: str | None,
        dry_run: bool,
        management_ip: str | None = None,
    ) -> None:
        self.nb = nb
        self.data = data
        self.device = device
        self.site = site
        self.cfg = cfg
        self.tag = tag
        self.tags = tag_ref(tag)
        self.dry_run = dry_run
        self.management_ip = management_ip
        self.report = Report()
        excludes = [re.compile(p) for p in cfg.exclude_interfaces]
        self.interfaces = [
            i for i in data.interfaces if not any(r.search(i.name) for r in excludes)
        ]
        self.iface_names = {i.name for i in self.interfaces}
        self.nb_ifaces: dict[str, Any] = {}
        self.vlans: dict[int, Any] = {}  # vid -> NetBox VLAN
        self.seen_prefixes: set[str] = set()

    # ------------------------------------------------------------------ helpers

    def _create(self, endpoint: Any, kind: str, payload: dict[str, Any], label: str) -> Any:
        log.debug("%s %s payload: %s", kind, label, payload)
        if self.dry_run:
            log.info("DRY-RUN: would create %s %s", kind, label)
            self.report.add(kind, "would_create")
            return SimpleNamespace(id=PLANNED, **{k: v for k, v in payload.items() if k != "tags"})
        try:
            record = endpoint.create({**payload, "tags": self.tags})
        except Exception as exc:
            raise NetBoxError(f"Creating {kind} {label} failed: {describe_api_error(exc)}") from exc
        log.info("Created %s %s (ID %s)", kind, label, record.id)
        self.report.add(kind, "created")
        return record

    def _fill_empty(self, record: Any, kind: str, label: str, values: dict[str, Any]) -> None:
        """Set only the fields that are currently empty on an existing record."""
        changes = {
            k: v for k, v in values.items() if v is not None and _is_empty(getattr(record, k, None))
        }
        if not changes:
            self.report.add(kind, "exists")
            return
        if self.dry_run or not _real(record):
            log.info("DRY-RUN: would fill %s %s: %s", kind, label, sorted(changes))
            self.report.add(kind, "would_update")
            return
        try:
            record.update(changes)
        except Exception as exc:
            raise NetBoxError(f"Updating {kind} {label} failed: {describe_api_error(exc)}") from exc
        log.info("Filled %s %s: %s", kind, label, sorted(changes))
        self.report.add(kind, "updated")

    def _step(self, name: str, enabled: bool, func: Any) -> None:
        if not enabled:
            return
        try:
            func()
        except Exception as exc:
            msg = f"{name}: {exc}"
            log.error(msg)
            self.report.errors.append(msg)

    # ------------------------------------------------------------------ steps

    def run(self) -> Report:
        cfg = self.cfg
        if self.tag:
            # Every created object references the tag - without it NetBox rejects them (HTTP 400).
            self._step("tag", True, lambda: ensure_tag(self.nb, self.tag, self.dry_run))
            if self.report.errors:
                log.error("Cannot ensure tag '%s' - aborting before any other change", self.tag)
                return self.report
        self._step("platform", cfg.sync_platform, self.sync_platform)
        self._step("vlans", cfg.sync_vlans, self.sync_vlans)
        self._step("interfaces", cfg.sync_interfaces, self.sync_interfaces)
        self._step("prefixes/ips", cfg.sync_prefixes or cfg.sync_interface_ips, self.sync_ips)
        self._step("dhcp ranges", cfg.sync_dhcp_ranges, self.sync_dhcp_ranges)
        self._step("dhcp reservations", cfg.sync_dhcp_reservations, self.sync_dhcp_reservations)
        self._step("dhcp leases", bool(cfg.dhcp_lease_interfaces), self.sync_dhcp_leases)
        for line in self.report.lines():
            log.info("  %s", line)
        log.info(
            "Network sync finished (dry_run=%s), errors=%d", self.dry_run, len(self.report.errors)
        )
        return self.report

    def sync_platform(self) -> None:
        cfg = self.cfg
        platform = self.nb.dcim.platforms.get(slug=cfg.platform_slug)
        if platform:
            self.report.add("platform", "exists")
        else:
            manufacturer = getattr(getattr(self.device, "device_type", None), "manufacturer", None)
            platform = self._create(
                self.nb.dcim.platforms,
                "platform",
                {
                    "name": cfg.platform_name,
                    "slug": cfg.platform_slug,
                    "manufacturer": getattr(manufacturer, "id", None),
                },
                cfg.platform_name,
            )
        self._fill_empty(self.device, "device", self.device.name, {"platform": platform.id})

        version = self.data.status.version
        custom = getattr(self.device, "custom_fields", None) or {}
        fw_field = cfg.firmware_custom_field
        if not version:
            return
        if fw_field not in custom:
            log.info(
                "Custom field '%s' (dcim.device, text) not found - FortiOS %s not recorded",
                fw_field,
                version,
            )
            return
        old = custom.get(fw_field)
        if old == version:
            self.report.add("firmware", "exists")
            return
        if self.dry_run or not _real(self.device):
            log.info("DRY-RUN: would set %s %s -> %s", fw_field, old, version)
            self.report.add("firmware", "would_update")
            return
        self.device.update({"custom_fields": {fw_field: version}})
        if old:
            self.nb.extras.journal_entries.create(
                {
                    "assigned_object_type": "dcim.device",
                    "assigned_object_id": self.device.id,
                    "kind": "info",
                    "comments": f"FortiOS changed: {old} -> {version} (netbox-discovery)",
                }
            )
        self.report.add("firmware", "updated")

    def _vlan_group(self) -> Any:
        slug = self.cfg.vlan_group_slug or f"{self.site.slug}-vlans"
        group = self.nb.ipam.vlan_groups.get(slug=slug)
        if group:
            self.report.add("vlan_group", "exists")
            return group
        return self._create(
            self.nb.ipam.vlan_groups,
            "vlan_group",
            {
                "name": f"{self.site.name} VLANs",
                "slug": slug,
                "scope_type": "dcim.site",
                "scope_id": self.site.id,
            },
            slug,
        )

    def sync_vlans(self) -> None:
        group = self._vlan_group()
        for iface in self.interfaces:
            if iface.type != "vlan" or not iface.vlan_id:
                continue
            vid = iface.vlan_id
            if vid in self.vlans:
                log.warning(
                    "VLAN %s used by more than one interface (%s) - only the first is created",
                    vid,
                    iface.name,
                )
                self.report.add("vlan", "skipped_duplicate")
                continue
            existing = self.nb.ipam.vlans.get(group_id=group.id, vid=vid) if _real(group) else None
            if existing:
                self.report.add("vlan", "exists")
                self.vlans[vid] = existing
                continue
            self.vlans[vid] = self._create(
                self.nb.ipam.vlans,
                "vlan",
                {
                    "vid": vid,
                    "name": iface.name,
                    "group": group.id,
                    "status": "active",
                    "description": (iface.alias or iface.description)[:DESCRIPTION_MAX],
                },
                f"{vid} {iface.name}",
            )

    def _interface_payload(
        self, iface: Interface, lag_of: dict[str, str], bridge_of: dict[str, str]
    ) -> dict[str, Any]:
        status = self.data.interface_status.get(iface.name)
        ids = {name: getattr(rec, "id", None) for name, rec in self.nb_ifaces.items()}
        payload: dict[str, Any] = {
            "device": self.device.id,
            "name": iface.name,
            "type": interface_type(iface, self.cfg),
            "enabled": iface.enabled,
            "mtu": iface.mtu,
            "label": iface.alias[:LABEL_MAX],
            "description": iface.description[:DESCRIPTION_MAX],
        }
        if iface.parent and iface.parent in ids:
            payload["parent"] = ids[iface.parent]
        if iface.name in lag_of and lag_of[iface.name] in ids:
            payload["lag"] = ids[lag_of[iface.name]]
        if iface.name in bridge_of and bridge_of[iface.name] in ids:
            payload["bridge"] = ids[bridge_of[iface.name]]
        if status and status.link:  # FortiOS reports speed/duplex garbage for down links
            if status.speed_mbps:
                payload["speed"] = status.speed_mbps * 1000  # NetBox uses kbps
            if status.duplex:
                payload["duplex"] = status.duplex
        vlan = self.vlans.get(iface.vlan_id or -1) if iface.type == "vlan" else None
        if vlan is not None:
            payload["mode"] = "access"
            payload["untagged_vlan"] = vlan.id
        tagged = [
            self.vlans[i.vlan_id].id
            for i in self.interfaces
            if i.type == "vlan" and i.parent == iface.name and i.vlan_id in self.vlans
        ]
        if tagged:
            payload["mode"] = "tagged"
            payload["tagged_vlans"] = [t for t in tagged if t is not None]
        return payload

    def sync_interfaces(self) -> None:
        existing = (
            {i.name: i for i in self.nb.dcim.interfaces.filter(device_id=self.device.id)}
            if _real(self.device)
            else {}
        )
        lag_of: dict[str, str] = {}
        bridge_of: dict[str, str] = {}
        for iface in self.interfaces:
            target = lag_of if IFACE_TYPE_MAP.get(iface.type) == "lag" else bridge_of
            for member in iface.members:
                target[member] = iface.name

        for iface in dependency_order(self.interfaces):
            if iface.name in existing:
                self.nb_ifaces[iface.name] = existing[iface.name]
                self.report.add("interface", "exists")
            else:
                payload = {
                    k: v
                    for k, v in self._interface_payload(iface, lag_of, bridge_of).items()
                    if v not in (None, "")
                }
                self.nb_ifaces[iface.name] = self._create(
                    self.nb.dcim.interfaces, "interface", payload, iface.name
                )
            self._sync_mac(iface)

    def _sync_mac(self, iface: Interface) -> None:
        status = self.data.interface_status.get(iface.name)
        mac = iface.mac or (status.mac if status else None)
        nb_iface = self.nb_ifaces[iface.name]
        if not mac:
            return
        existing = (
            list(self.nb.dcim.mac_addresses.filter(mac_address=mac, interface_id=nb_iface.id))
            if _real(nb_iface)
            else []
        )
        if existing:
            record = existing[0]
            self.report.add("mac_address", "exists")
        else:
            record = self._create(
                self.nb.dcim.mac_addresses,
                "mac_address",
                {
                    "mac_address": mac,
                    "assigned_object_type": "dcim.interface",
                    "assigned_object_id": nb_iface.id,
                },
                f"{mac} ({iface.name})",
            )
        self._fill_empty(nb_iface, "primary_mac", iface.name, {"primary_mac_address": record.id})

    # ------------------------------------------------------------------ IP addressing

    def _prefix(self, network: Any, description: str, vlan: Any | None) -> None:
        if not self.cfg.sync_prefixes or str(network) in self.seen_prefixes:
            return
        self.seen_prefixes.add(str(network))
        existing = list(self.nb.ipam.prefixes.filter(prefix=str(network), vrf_id="null"))
        values = {
            "scope_type": "dcim.site",
            "scope_id": self.site.id,
            "vlan": getattr(vlan, "id", None),
            "description": description[:DESCRIPTION_MAX],
        }
        if existing:
            record = existing[0]
            if not _is_empty(getattr(record, "scope_id", None)):
                values.pop("scope_type")
                values.pop("scope_id")
            self._fill_empty(record, "prefix", str(network), values)
            return
        self._create(
            self.nb.ipam.prefixes,
            "prefix",
            {"prefix": str(network), "status": "active", **{k: v for k, v in values.items() if v}},
            str(network),
        )

    def _ip(
        self,
        address: IPv4Interface | IPv6Interface,
        *,
        status: str,
        role: str | None = None,
        interface: Any | None = None,
        description: str = "",
        dns: str = "",
    ) -> Any:
        host = str(address.ip)
        existing = list(self.nb.ipam.ip_addresses.filter(address=host))
        assign = (
            {"assigned_object_type": "dcim.interface", "assigned_object_id": interface.id}
            if interface is not None
            else {}
        )
        if existing:
            record = existing[0]
            if interface is not None and record.assigned_object_id not in (None, interface.id):
                log.warning("IP %s is assigned to another object in NetBox - not changed", host)
                self.report.add("ip_address", "conflict")
                return record
            self._fill_empty(
                record,
                "ip_address",
                host,
                {**assign, "dns_name": dns or None, "description": description or None},
            )
            return record
        payload: dict[str, Any] = {
            "address": str(address),
            "status": status,
            "description": description[:DESCRIPTION_MAX],
            **assign,
        }
        if role:
            payload["role"] = role
        if dns:
            payload["dns_name"] = dns
        return self._create(self.nb.ipam.ip_addresses, "ip_address", payload, str(address))

    def sync_ips(self) -> None:
        primary = None
        for iface in self.interfaces:
            if iface.ip is None:
                continue
            vlan = self.vlans.get(iface.vlan_id or -1) if iface.type == "vlan" else None
            label = iface.alias or iface.name
            addresses = [(iface.ip, None), *[(s, "secondary") for s in iface.secondary_ips]]
            for address, role in addresses:
                self._prefix(address.network, label, vlan)
                if not self.cfg.sync_interface_ips:
                    continue
                record = self._ip(
                    address,
                    status="active",
                    role=role,
                    interface=self.nb_ifaces.get(iface.name),
                    description=f"FortiGate {iface.name}",
                )
                if self._is_management(iface, address):
                    primary = record
        if primary is not None and self.cfg.sync_interface_ips:
            self._fill_empty(self.device, "device", self.device.name, {"primary_ip4": primary.id})

    def _is_management(self, iface: Interface, address: IPv4Interface) -> bool:
        if self.cfg.management_interface:
            return iface.name == self.cfg.management_interface and address == iface.ip
        return self.management_ip is not None and str(address.ip) == self.management_ip

    # ------------------------------------------------------------------ DHCP

    def _servers(self) -> Iterable[tuple[DhcpServer, int]]:
        for server in self.data.dhcp_servers:
            if not server.enabled or server.interface not in self.iface_names:
                continue
            try:
                prefixlen = ip_interface(f"0.0.0.0/{server.netmask}").network.prefixlen
            except ValueError:
                continue
            yield server, prefixlen

    def sync_dhcp_ranges(self) -> None:
        for server, plen in self._servers():
            for rng in server.ip_ranges:
                start, end = rng.get("start-ip"), rng.get("end-ip")
                if not start or not end:
                    continue
                label = f"{start}-{end}"
                existing = list(
                    self.nb.ipam.ip_ranges.filter(
                        start_address=start, end_address=end, vrf_id="null"
                    )
                )
                if existing:
                    self.report.add("ip_range", "exists")
                    continue
                dns = ", ".join(server.dns_servers)
                desc = f"DHCP pool {server.interface}" + (f" (DNS {dns})" if dns else "")
                self._create(
                    self.nb.ipam.ip_ranges,
                    "ip_range",
                    {
                        "start_address": f"{start}/{plen}",
                        "end_address": f"{end}/{plen}",
                        "status": "active",
                        "description": desc[:DESCRIPTION_MAX],
                    },
                    label,
                )

    def sync_dhcp_reservations(self) -> None:
        for server, plen in self._servers():
            for res in server.reserved_addresses:
                ip = res.get("ip")
                if not ip:
                    continue
                mac = (res.get("mac") or "").lower()
                desc = " ".join(
                    p for p in ("DHCP reservation", mac, res.get("description") or "") if p
                )
                self._ip(ip_interface(f"{ip}/{plen}"), status="reserved", description=desc)

    def sync_dhcp_leases(self) -> None:
        wanted = set(self.cfg.dhcp_lease_interfaces)
        plen_by_iface = {s.interface: plen for s, plen in self._servers()}
        for lease in self.data.dhcp_leases:
            if lease.interface not in wanted or lease.reserved or not lease.ip:
                continue
            plen = plen_by_iface.get(lease.interface)
            if plen is None or ip_address(lease.ip).version != 4:
                continue
            desc = " ".join(p for p in ("DHCP lease", lease.mac, lease.vci or "") if p)
            self._ip(
                ip_interface(f"{lease.ip}/{plen}"),
                status="dhcp",
                description=desc,
                dns=dns_name(lease.hostname),
            )
