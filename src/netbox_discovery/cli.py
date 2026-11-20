"""Command line interface: ``netbox-discovery <command> [--apply]``.

Everything runs in dry-run mode unless ``--apply`` is given.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections import Counter
from collections.abc import Sequence
from functools import partial
from ipaddress import ip_address
from urllib.parse import urlparse

from netbox_discovery import __version__
from netbox_discovery.config import ConfigError, Settings, load_settings, require_token
from netbox_discovery.config import requests_verify as verify_value
from netbox_discovery.logsetup import mask, setup_logging
from netbox_discovery.netbox_client import build_api
from netbox_discovery.sources.fortigate import FortiGateClient
from netbox_discovery.sources.nmap import scan_network
from netbox_discovery.sync import fortigate_device, fortigate_network
from netbox_discovery.sync.ip_sync import sync_networks

log = logging.getLogger("netbox_discovery")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFIG = 2


def _fortigate(settings: Settings) -> FortiGateClient:
    fg = settings.fortigate
    if not fg.enabled:
        raise ConfigError("FortiGate is disabled (fortigate.enabled: false)")
    if fg.url is None:
        raise ConfigError("fortigate.url is not configured")
    return FortiGateClient(
        url=str(fg.url),
        token=require_token(fg.token, "fortigate"),
        verify=verify_value(fg.verify, "FortiGate"),
        vdom=fg.vdom,
        timeout=fg.timeout,
    )


def cmd_scan(settings: Settings, args: argparse.Namespace) -> int:
    if not settings.discovery.networks:
        raise ConfigError("discovery.networks is empty")
    nb = build_api(settings.netbox)
    report = sync_networks(
        nb,
        settings.discovery.networks,
        partial(scan_network, timeout=settings.discovery.nmap_timeout),
        dry_run=not args.apply,
        tag=settings.sync.tag,
        status=settings.sync.ip_status,
        description=settings.sync.ip_description,
    )
    return EXIT_OK if report.ok else EXIT_ERROR


def cmd_fortigate_device(settings: Settings, args: argparse.Namespace) -> int:
    cfg = settings.fortigate_device
    fg = _fortigate(settings)
    nb = build_api(settings.netbox)
    identity = fortigate_device.discover(fg)
    plan = fortigate_device.build_plan(nb, identity, cfg)
    fortigate_device.log_plan(plan, cfg)
    if plan.action is fortigate_device.Action.CREATE and not args.apply:
        log.info("DRY-RUN: nothing was written. Re-run with --apply to create the device.")
        return EXIT_OK
    device = fortigate_device.apply_plan(nb, plan, cfg, settings.sync.tag)
    if device is not None:
        log.info("Device created: %s (ID %s)", device.name, device.id)
    return EXIT_OK


def _management_ip(settings: Settings) -> str | None:
    host = urlparse(str(settings.fortigate.url)).hostname if settings.fortigate.url else None
    try:
        return str(ip_address(host)) if host else None
    except ValueError:
        return None


def cmd_fortigate_network(settings: Settings, args: argparse.Namespace) -> int:
    net_cfg = settings.fortigate_network
    fg = _fortigate(settings)
    nb = build_api(settings.netbox)
    data = fortigate_network.discover(fg, with_leases=bool(net_cfg.dhcp_lease_interfaces))
    if not data.status.serial:
        raise ConfigError("FortiGate did not report a serial number")
    devices = list(nb.dcim.devices.filter(serial=data.status.serial))
    if len(devices) != 1:
        log.error(
            "Expected exactly one NetBox device with the FortiGate serial, found %d - "
            "run 'netbox-discovery fortigate-device --apply' first",
            len(devices),
        )
        return EXIT_ERROR
    device = devices[0]
    site_id = getattr(device.site, "id", device.site)
    site = nb.dcim.sites.get(site_id)
    log.info("Device: %s (ID %s), site: %s", device.name, device.id, site.name)
    report = fortigate_network.NetworkSync(
        nb,
        data,
        device,
        site,
        net_cfg,
        tag=settings.sync.tag,
        dry_run=not args.apply,
        management_ip=_management_ip(settings),
    ).run()
    if not args.apply:
        log.info("DRY-RUN: nothing was written. Re-run with --apply to apply the changes.")
    return EXIT_OK if report.ok else EXIT_ERROR


def cmd_fortigate_status(settings: Settings, args: argparse.Namespace) -> int:
    fg = _fortigate(settings)
    status = fg.get_system_status()
    print(f"Hostname: {status.hostname}")
    print(f"Model:    {status.display_model}")
    print(f"Serial:   {mask(status.serial)}")
    print(f"FortiOS:  {status.version} (build {status.build})")
    servers = fg.get_dhcp_servers()
    print(f"\nDHCP servers: {len(servers)}")
    for s in servers:
        print(f"  #{s.id} {s.interface}: gw={s.gateway} mask={s.netmask} ranges={s.ip_ranges}")
        print(f"     reservations: {len(s.reserved_addresses)}")
    return EXIT_OK


def cmd_fortigate_dhcp_report(settings: Settings, args: argparse.Namespace) -> int:
    leases = _fortigate(settings).get_dhcp_leases()
    print(f"DHCP leases: {len(leases)}")
    print("\nBy interface:")
    for iface, count in sorted(Counter(lease.interface for lease in leases).items(), key=str):
        print(f"  {iface}: {count}")
    print("\nBy status:")
    for st, count in Counter(lease.status for lease in leases).items():
        print(f"  {st}: {count}")
    print("\nData quality:")
    print(f"  with MAC:      {sum(bool(x.mac) for x in leases)}")
    print(f"  with hostname: {sum(bool(x.hostname) for x in leases)}")
    print(f"  reserved:      {sum(x.reserved for x in leases)}")
    if args.limit:
        print(f"\nFirst {args.limit} leases:")
        for x in leases[: args.limit]:
            print(
                f"  {x.ip} | {x.mac} | {x.hostname} | {x.interface} | {x.status} | {x.expires_at}"
            )
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netbox-discovery", description=__doc__)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "-c", "--config", help="YAML config (default: $NBD_CONFIG or config/config.yaml)"
    )
    parser.add_argument(
        "--env-file", default=".env", help="dotenv file with secrets (default: .env)"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="nmap ping scan -> create missing IP addresses in NetBox")
    p.add_argument("--apply", action="store_true", help="write to NetBox (default: dry-run)")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("fortigate-device", help="create the FortiGate device in NetBox")
    p.add_argument("--apply", action="store_true", help="write to NetBox (default: dry-run)")
    p.set_defaults(func=cmd_fortigate_device)

    p = sub.add_parser(
        "fortigate-network",
        help="FortiGate interfaces, VLANs, prefixes, IPs and DHCP data -> NetBox",
    )
    p.add_argument("--apply", action="store_true", help="write to NetBox (default: dry-run)")
    p.set_defaults(func=cmd_fortigate_network)

    p = sub.add_parser(
        "fortigate-status", help="show FortiGate status and DHCP servers (read-only)"
    )
    p.set_defaults(func=cmd_fortigate_status)

    p = sub.add_parser("fortigate-dhcp-report", help="summarize FortiGate DHCP leases (read-only)")
    p.add_argument("--limit", type=int, default=10, help="number of sample leases to print")
    p.set_defaults(func=cmd_fortigate_dhcp_report)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose)
    try:
        settings = load_settings(args.config, args.env_file)
        result: int = args.func(settings, args)
    except ConfigError as exc:
        log.error("%s", exc)
        return EXIT_CONFIG
    except Exception as exc:
        log.error("%s", exc, exc_info=args.verbose)
        return EXIT_ERROR
    return result


if __name__ == "__main__":
    sys.exit(main())
