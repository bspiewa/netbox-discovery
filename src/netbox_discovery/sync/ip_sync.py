"""nmap scan -> IP addresses in NetBox."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from ipaddress import IPv4Network, IPv6Network
from typing import Any

from netbox_discovery.netbox_client import IpResult, ensure_tag, upsert_ip
from netbox_discovery.sources.nmap import Host

log = logging.getLogger(__name__)

Scanner = Callable[[IPv4Network | IPv6Network], list[Host]]


@dataclass
class SyncReport:
    counts: dict[IpResult, int] = field(default_factory=lambda: dict.fromkeys(IpResult, 0))
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def summary(self) -> str:
        parts = [f"{k.value}={v}" for k, v in self.counts.items()]
        parts.append(f"errors={len(self.errors)}")
        return ", ".join(parts)


def sync_networks(
    nb: Any,
    networks: Iterable[IPv4Network | IPv6Network],
    scanner: Scanner,
    *,
    dry_run: bool,
    tag: str | None,
    status: str,
    description: str,
) -> SyncReport:
    """Scan every network and create missing IPs. Errors are collected, not fatal."""
    report = SyncReport()
    if tag:
        ensure_tag(nb, tag, dry_run)

    for network in networks:
        try:
            hosts = scanner(network)
        except Exception as exc:
            msg = f"scan of {network} failed: {exc}"
            log.error(msg)
            report.errors.append(msg)
            continue

        for host in hosts:
            try:
                result = upsert_ip(
                    nb, host.ip, dry_run=dry_run, status=status, description=description, tag=tag
                )
            except Exception as exc:
                msg = f"{host.ip}: {exc}"
                log.error(msg)
                report.errors.append(msg)
                continue
            report.counts[result] += 1

    log.info("IP sync finished (dry_run=%s): %s", dry_run, report.summary())
    return report
