"""Host discovery with nmap ping scan (``nmap -sn``)."""

from __future__ import annotations

import logging
import shutil
import subprocess
import xml.etree.ElementTree as ET  # input is nmap's own output, not external XML
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network, ip_network

log = logging.getLogger(__name__)

Runner = Callable[..., "subprocess.CompletedProcess[str]"]


class NmapError(RuntimeError):
    """nmap failed or returned unparsable output."""


@dataclass(frozen=True)
class Host:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None


def build_command(network: IPv4Network | IPv6Network | str) -> list[str]:
    """Build the nmap argv. The target is validated and placed after ``--``."""
    net = ip_network(str(network))  # raises ValueError on anything that is not a network
    cmd = ["nmap", "-sn", "-oX", "-"]
    if net.version == 6:
        cmd.append("-6")
    return [*cmd, "--", str(net)]


def parse_xml(xml_text: str) -> list[Host]:
    """Parse ``nmap -oX`` output into a list of hosts that are up."""
    try:
        root = ET.fromstring(xml_text)  # noqa: S314 - trusted local nmap output
    except ET.ParseError as exc:
        raise NmapError(f"Cannot parse nmap XML output: {exc}") from exc

    hosts: list[Host] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = mac = vendor = None
        for address in host.findall("address"):
            addrtype = address.get("addrtype")
            if addrtype in ("ipv4", "ipv6"):
                ip = address.get("addr")
            elif addrtype == "mac":
                mac = (address.get("addr") or "").lower() or None
                vendor = address.get("vendor")

        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else None

        if ip:
            hosts.append(Host(ip=ip, mac=mac, vendor=vendor, hostname=hostname))
    return hosts


def scan_network(
    network: IPv4Network | IPv6Network | str,
    timeout: int = 600,
    runner: Runner = subprocess.run,
) -> list[Host]:
    """Run a ping scan of ``network`` and return the hosts that are up."""
    cmd = build_command(network)
    if runner is subprocess.run and shutil.which("nmap") is None:
        raise NmapError("nmap binary not found in PATH")

    log.info("Scanning %s", cmd[-1])
    try:
        result = runner(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise NmapError(f"nmap timed out after {timeout}s for {cmd[-1]}") from exc

    if result.returncode != 0:
        raise NmapError(f"nmap exited with {result.returncode}: {result.stderr.strip()}")

    hosts = parse_xml(result.stdout)
    log.info("Found %d hosts up in %s", len(hosts), cmd[-1])
    return hosts
