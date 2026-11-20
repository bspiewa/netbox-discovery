"""FortiGate -> NetBox device (dcim.device) synchronization.

Flow: ``discover()`` reads identity from FortiGate, ``build_plan()`` inspects NetBox
(read-only), ``apply_plan()`` performs the writes. Existing devices are never modified.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from netbox_discovery.config import FortiGateDeviceSettings
from netbox_discovery.logsetup import mask
from netbox_discovery.netbox_client import create_and_verify, ensure_tag, tag_ref
from netbox_discovery.sources.fortigate import FortiGateClient

log = logging.getLogger(__name__)

PLACEHOLDER_SERIALS = {"ukryty", "hidden", "unknown", "none", "n/a", ""}


class SyncError(RuntimeError):
    """Synchronization cannot continue safely - manual check required."""


@dataclass(frozen=True)
class Identity:
    hostname: str
    serial: str
    model: str  # NetBox device type model, e.g. "FortiGate 70G"
    version: str | None


class Action(StrEnum):
    EXISTS = "exists"
    CREATE = "create"
    DISABLED = "disabled"


@dataclass
class DevicePlan:
    identity: Identity
    site: Any
    manufacturer: Any
    role: Any | None  # None -> to be created
    device_type: Any | None  # None -> to be created
    device_type_model: str
    device_type_slug: str
    action: Action
    existing_device: Any | None = None


def slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def discover(fg: FortiGateClient) -> Identity:
    status = fg.get_system_status()
    model = status.display_model
    if not status.hostname or not status.serial or not model:
        raise SyncError("Missing FortiGate identity information (hostname/serial/model)")
    if status.serial.strip().lower() in PLACEHOLDER_SERIALS:
        raise SyncError(
            "FortiGate serial appears to be a placeholder - check API admin profile permissions"
        )
    identity = Identity(
        hostname=status.hostname, serial=status.serial, model=model, version=status.version
    )
    log.info(
        "FortiGate: hostname=%s model=%s serial=%s FortiOS=%s",
        identity.hostname,
        identity.model,
        mask(identity.serial),
        identity.version,
    )
    return identity


def build_plan(nb: Any, identity: Identity, cfg: FortiGateDeviceSettings) -> DevicePlan:
    """Inspect NetBox (read-only) and decide what needs to be created."""
    if not cfg.site_slug:
        raise SyncError("fortigate_device.site_slug is not configured")

    site = nb.dcim.sites.get(slug=cfg.site_slug)
    if not site:
        raise SyncError(f"Site '{cfg.site_slug}' does not exist in NetBox")

    manufacturer = nb.dcim.manufacturers.get(slug=cfg.manufacturer_slug)
    if not manufacturer:
        raise SyncError(f"Manufacturer '{cfg.manufacturer_slug}' does not exist in NetBox")

    role = nb.dcim.device_roles.get(slug=cfg.role_slug)

    dt_model = cfg.device_type_model or identity.model
    dt_slug = cfg.device_type_slug or slugify(dt_model)
    device_type = nb.dcim.device_types.get(slug=dt_slug)
    if device_type:
        dt_manufacturer = getattr(device_type, "manufacturer", None)
        dt_manufacturer_id = getattr(dt_manufacturer, "id", dt_manufacturer)
        if dt_manufacturer_id != manufacturer.id:
            raise SyncError(f"Device type '{dt_slug}' exists but has a different manufacturer")

    serial_matches = list(nb.dcim.devices.filter(serial=identity.serial))
    if len(serial_matches) > 1:
        raise SyncError("Multiple NetBox devices share the FortiGate serial number")

    existing = serial_matches[0] if serial_matches else None
    if existing is None and nb.dcim.devices.get(name=identity.hostname):
        raise SyncError(f"Device name '{identity.hostname}' already exists with a different serial")

    if existing is not None:
        action = Action.EXISTS
        if existing.name != identity.hostname:
            log.warning(
                "Existing device name '%s' differs from FortiGate hostname '%s'",
                existing.name,
                identity.hostname,
            )
    elif cfg.create_device:
        action = Action.CREATE
    else:
        action = Action.DISABLED

    return DevicePlan(
        identity=identity,
        site=site,
        manufacturer=manufacturer,
        role=role,
        device_type=device_type,
        device_type_model=dt_model,
        device_type_slug=dt_slug,
        action=action,
        existing_device=existing,
    )


def log_plan(plan: DevicePlan, cfg: FortiGateDeviceSettings) -> None:
    log.info("Site: %s (ID %s)", plan.site.name, plan.site.id)
    log.info("Manufacturer: %s (ID %s)", plan.manufacturer.name, plan.manufacturer.id)
    if plan.role:
        log.info("Device role: %s (ID %s)", plan.role.name, plan.role.id)
    else:
        log.info("Device role: MISSING -> create '%s'", cfg.role_name)
    if plan.device_type:
        log.info("Device type: %s (ID %s)", plan.device_type.model, plan.device_type.id)
    else:
        log.info("Device type: MISSING -> create '%s'", plan.device_type_model)

    existing = plan.existing_device
    if plan.action is Action.EXISTS and existing is not None:
        log.info("Device exists: %s (ID %s) - no changes", existing.name, existing.id)
    elif plan.action is Action.DISABLED:
        log.info("Device missing, creation disabled (fortigate_device.create_device=false)")
    else:
        log.info(
            "Device missing -> create name=%s serial=%s site=%s status=active",
            plan.identity.hostname,
            mask(plan.identity.serial),
            plan.site.slug,
        )


def apply_plan(nb: Any, plan: DevicePlan, cfg: FortiGateDeviceSettings, tag: str | None) -> Any:
    """Execute the plan. Returns the created device or None."""
    if plan.action is not Action.CREATE:
        return None

    tags = tag_ref(tag)
    if tag:
        ensure_tag(nb, tag, dry_run=False)

    role = plan.role or create_and_verify(
        nb.dcim.device_roles,
        {"name": cfg.role_name, "slug": cfg.role_slug, "color": cfg.role_color, "tags": tags},
        {"slug": cfg.role_slug},
        "Device role",
    )
    device_type = plan.device_type or create_and_verify(
        nb.dcim.device_types,
        {
            "manufacturer": plan.manufacturer.id,
            "model": plan.device_type_model,
            "slug": plan.device_type_slug,
            "tags": tags,
        },
        {"slug": plan.device_type_slug},
        "Device type",
    )
    device = create_and_verify(
        nb.dcim.devices,
        {
            "name": plan.identity.hostname,
            "serial": plan.identity.serial,
            "device_type": device_type.id,
            "role": role.id,
            "site": plan.site.id,
            "status": "active",
            "tags": tags,
        },
        {"serial": plan.identity.serial},
        "Device",
    )
    if getattr(device, "name", None) != plan.identity.hostname:
        raise SyncError("Created device name differs from FortiGate hostname")
    return device
