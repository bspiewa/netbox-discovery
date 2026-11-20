"""Read-only FortiGate (FortiOS REST API v2) client."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import requests

log = logging.getLogger(__name__)


class FortiGateError(RuntimeError):
    """FortiGate API returned an error."""


@dataclass(frozen=True)
class SystemStatus:
    hostname: str | None
    serial: str | None
    model: str | None  # e.g. "FGT70G"
    model_name: str | None  # e.g. "FortiGate"
    model_number: str | None  # e.g. "70G"
    version: str | None
    build: int | None

    @property
    def display_model(self) -> str | None:
        """Human readable model, e.g. "FortiGate 70G"."""
        if self.model_name and self.model_number:
            return f"{self.model_name} {self.model_number}"
        return self.model


@dataclass(frozen=True)
class DhcpLease:
    ip: str | None
    mac: str
    hostname: str | None
    interface: str | None
    status: str | None
    reserved: bool
    vci: str | None
    expires_at: str | None
    dhcp_server_id: int | None


@dataclass(frozen=True)
class DhcpServer:
    id: int | None
    interface: str | None
    gateway: str | None
    netmask: str | None
    ip_ranges: list[dict[str, Any]]
    reserved_addresses: list[dict[str, Any]]


def parse_system_status(data: dict[str, Any]) -> SystemStatus:
    results = data.get("results") or {}
    return SystemStatus(
        hostname=results.get("hostname"),
        serial=data.get("serial") or results.get("serial"),
        model=results.get("model"),
        model_name=results.get("model_name"),
        model_number=results.get("model_number"),
        version=data.get("version"),
        build=data.get("build"),
    )


def parse_dhcp_leases(data: dict[str, Any]) -> list[DhcpLease]:
    leases = []
    for item in data.get("results", []):
        expire_time = item.get("expire_time")
        expires_at = (
            datetime.fromtimestamp(expire_time, tz=UTC).isoformat() if expire_time else None
        )
        leases.append(
            DhcpLease(
                ip=item.get("ip"),
                mac=(item.get("mac") or "").lower(),
                hostname=item.get("hostname"),
                interface=item.get("interface"),
                status=item.get("status"),
                reserved=bool(item.get("reserved", False)),
                vci=item.get("vci"),
                expires_at=expires_at,
                dhcp_server_id=item.get("server_mkey"),
            )
        )
    return leases


def parse_dhcp_servers(data: dict[str, Any]) -> list[DhcpServer]:
    return [
        DhcpServer(
            id=s.get("id"),
            interface=s.get("interface"),
            gateway=s.get("default-gateway"),
            netmask=s.get("netmask"),
            ip_ranges=s.get("ip-range", []),
            reserved_addresses=s.get("reserved-address", []),
        )
        for s in data.get("results", [])
    ]


class FortiGateClient:
    """Minimal read-only FortiOS REST API client (Bearer token auth)."""

    def __init__(
        self,
        url: str,
        token: str,
        *,
        verify: bool | str = True,
        vdom: str = "root",
        timeout: int = 20,
        session: requests.Session | None = None,
    ) -> None:
        if not url or not token:
            raise ValueError("FortiGate URL and token are required")
        self.base_url = url.rstrip("/")
        self.vdom = vdom
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers["Authorization"] = f"Bearer {token}"
        self.session.verify = verify

    def __repr__(self) -> str:  # never expose the token
        return f"FortiGateClient(base_url={self.base_url!r}, vdom={self.vdom!r})"

    def get(self, endpoint: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.base_url}/api/v2/{endpoint}"
        response = self.session.get(
            url, params={"vdom": self.vdom, **(params or {})}, timeout=self.timeout
        )
        if response.status_code in (401, 403):
            raise FortiGateError(
                f"FortiGate rejected the API token (HTTP {response.status_code}) for {endpoint}"
            )
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        if data.get("status") not in (None, "success"):
            raise FortiGateError(f"FortiGate API error for {endpoint}: {data.get('status')}")
        return data

    def get_system_status(self) -> SystemStatus:
        return parse_system_status(self.get("monitor/system/status"))

    def get_dhcp_leases(self) -> list[DhcpLease]:
        return parse_dhcp_leases(self.get("monitor/system/dhcp"))

    def get_dhcp_servers(self) -> list[DhcpServer]:
        return parse_dhcp_servers(self.get("cmdb/system.dhcp/server"))

    def get_interfaces(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = self.get("cmdb/system/interface").get("results", [])
        return results
