"""NetBox access helpers built on pynetbox (no module-level state)."""

from __future__ import annotations

import logging
from enum import StrEnum
from ipaddress import ip_address
from typing import Any

import pynetbox

from netbox_discovery.config import NetBoxSettings, requests_verify, require_token

log = logging.getLogger(__name__)

MAX_ERROR_BODY = 500


class NetBoxError(RuntimeError):
    """A NetBox operation failed or returned unexpected data."""


def build_api(settings: NetBoxSettings) -> Any:
    """Create a pynetbox API client from settings."""
    api = pynetbox.api(str(settings.url).rstrip("/"), token=require_token(settings.token, "netbox"))
    api.http_session.verify = requests_verify(settings.verify, "NetBox")
    return api


def describe_api_error(exc: BaseException) -> str:
    """Readable description of a pynetbox/requests error, with the response body truncated."""
    details = [str(exc)]
    error = getattr(exc, "error", None)
    if error:
        details.append(f"API error: {str(error)[:MAX_ERROR_BODY]}")
    response = getattr(exc, "req", None) or getattr(exc, "response", None)
    if response is not None:
        status = getattr(response, "status_code", None)
        if status is not None:
            details.append(f"HTTP status: {status}")
    return " | ".join(details)


def tag_ref(tag_slug: str | None) -> list[dict[str, str]]:
    return [{"slug": tag_slug}] if tag_slug else []


def create_and_verify(
    endpoint: Any, data: dict[str, Any], lookup: dict[str, Any], label: str
) -> Any:
    """Create a record, then re-read it by ``lookup`` and check that the IDs match."""
    log.info("Creating %s ...", label)
    try:
        created = endpoint.create(data)
    except Exception as exc:
        raise NetBoxError(f"{label} creation failed: {describe_api_error(exc)}") from exc

    record_id = getattr(created, "id", None)
    if record_id is None:
        raise NetBoxError(f"{label} creation returned no ID")

    try:
        verified = endpoint.get(**lookup)
    except Exception as exc:
        raise NetBoxError(f"{label} verification failed: {describe_api_error(exc)}") from exc

    verified_id = getattr(verified, "id", None)
    if verified_id != record_id:
        raise NetBoxError(
            f"{label} verification failed: created ID {record_id}, found ID {verified_id}"
        )
    log.info("%s created and verified (ID %s)", label, record_id)
    return verified


def ensure_tag(nb: Any, slug: str, dry_run: bool) -> None:
    """Make sure the tag used to mark managed objects exists."""
    if nb.extras.tags.get(slug=slug):
        return
    if dry_run:
        log.info("DRY-RUN: tag '%s' would be created", slug)
        return
    create_and_verify(
        nb.extras.tags,
        {
            "name": slug,
            "slug": slug,
            "color": "2196f3",
            "description": "Managed by netbox-discovery",
        },
        {"slug": slug},
        f"Tag '{slug}'",
    )


class IpResult(StrEnum):
    EXISTS = "exists"
    CREATED = "created"
    WOULD_CREATE = "would_create"


def host_prefix_length(nb: Any, ip: str) -> int:
    """Mask length of the most specific NetBox prefix containing ``ip`` (host mask if none)."""
    addr = ip_address(ip)
    prefixes = list(nb.ipam.prefixes.filter(contains=ip))
    if prefixes:
        return max(int(str(p.prefix).split("/")[1]) for p in prefixes)
    return addr.max_prefixlen


def upsert_ip(
    nb: Any,
    ip: str,
    *,
    dry_run: bool,
    status: str = "active",
    description: str = "",
    tag: str | None = None,
) -> IpResult:
    """Create an IP address in NetBox if it does not exist yet (idempotent).

    Existing addresses are never modified.
    """
    existing = list(nb.ipam.ip_addresses.filter(address=ip))
    if existing:
        if len(existing) > 1:
            log.warning(
                "IP %s exists %d times in NetBox (check VRFs/duplicates)", ip, len(existing)
            )
        log.debug("IP exists: %s", ip)
        return IpResult.EXISTS

    address = f"{ip}/{host_prefix_length(nb, ip)}"
    if dry_run:
        log.info("DRY-RUN: would create IP %s", address)
        return IpResult.WOULD_CREATE

    try:
        nb.ipam.ip_addresses.create(
            {
                "address": address,
                "status": status,
                "description": description,
                "tags": tag_ref(tag),
            }
        )
    except Exception as exc:
        raise NetBoxError(f"Creating IP {address} failed: {describe_api_error(exc)}") from exc
    log.info("Created IP %s", address)
    return IpResult.CREATED
