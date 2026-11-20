"""Application configuration.

Sources, highest priority first:
  1. environment variables (prefix ``NBD_``, nested with ``__``, e.g. ``NBD_NETBOX__TOKEN``)
  2. ``.env`` file (same variable names)
  3. YAML config file (``--config`` / ``NBD_CONFIG`` / ``config/config.yaml``)
  4. defaults defined below

Secrets (API tokens) belong in env / ``.env`` only - never in the YAML file.
"""

from __future__ import annotations

import logging
import os
import stat
from contextvars import ContextVar
from ipaddress import IPv4Network, IPv6Network
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, FilePath, HttpUrl, SecretStr
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

log = logging.getLogger(__name__)

_yaml_path: ContextVar[Path | None] = ContextVar("nbd_yaml_path", default=None)

DEFAULT_CONFIG_PATH = Path("config/config.yaml")
DEFAULT_ENV_FILE = Path(".env")

# Pre-0.2 variable names, still accepted with a deprecation warning.
LEGACY_TOKEN_ENV = {
    "NBD_NETBOX__TOKEN": "NETBOX_TOKEN",
    "NBD_FORTIGATE__TOKEN": "FORTIGATE_TOKEN",
}


class ConfigError(Exception):
    """Invalid or incomplete configuration."""


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NetBoxSettings(_Section):
    url: HttpUrl
    token: SecretStr | None = None
    # True, False, or a path to a CA bundle (PEM) used to verify the server certificate.
    verify: bool | FilePath = True
    timeout: int = Field(default=30, gt=0)


class FortiGateSettings(_Section):
    enabled: bool = False
    url: HttpUrl | None = None
    token: SecretStr | None = None
    verify: bool | FilePath = True
    vdom: str = "root"
    timeout: int = Field(default=20, gt=0)


class DiscoverySettings(_Section):
    networks: list[IPv4Network | IPv6Network] = Field(default_factory=list)
    nmap_timeout: int = Field(default=600, gt=0)


class SyncSettings(_Section):
    # Tag attached to every object created by this tool (netbox-ssot / netbox-sync pattern).
    tag: str = "netbox-discovery"
    ip_status: str = "active"
    ip_description: str = "Discovered by nmap"


class FortiGateDeviceSettings(_Section):
    site_slug: str | None = None
    create_device: bool = True
    role_name: str = "Firewall"
    role_slug: str = "firewall"
    role_color: str = Field(default="607d8b", pattern=r"^[0-9a-fA-F]{6}$")
    manufacturer_slug: str = "fortinet"
    # Optional overrides; by default derived from the model reported by FortiGate.
    device_type_model: str | None = None
    device_type_slug: str | None = None


class FortiGateNetworkSettings(_Section):
    """FortiGate interfaces / VLANs / prefixes / IPs / DHCP -> NetBox (``fortigate-network``)."""

    sync_platform: bool = True
    sync_interfaces: bool = True
    sync_vlans: bool = True
    sync_prefixes: bool = True
    sync_interface_ips: bool = True
    sync_dhcp_ranges: bool = True
    sync_dhcp_reservations: bool = True
    # Opt-in: DHCP leases become IPs with status "dhcp" only for these FortiGate interfaces.
    dhcp_lease_interfaces: list[str] = Field(default_factory=list)

    platform_name: str = "FortiOS"
    platform_slug: str = "fortios"
    # Regexes of FortiGate interface names to ignore (internal/system interfaces by default).
    exclude_interfaces: list[str] = Field(default_factory=lambda: [r"^(naf|l2t|ssl)\.", r"^wqt"])
    # NetBox interface type for FortiGate "physical" ports, with per-name overrides.
    physical_interface_type: str = "1000base-t"
    interface_type_overrides: dict[str, str] = Field(default_factory=dict)
    # VLAN group (scoped to the site); default slug: "<site_slug>-vlans".
    vlan_group_slug: str | None = None
    # Interface whose IP becomes the device primary IPv4; default: the one holding fortigate.url.
    management_interface: str | None = None
    # NetBox custom field (dcim.device, text) for the FortiOS version - used only if it exists.
    firmware_custom_field: str = "firmware_version"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NBD_",
        env_nested_delimiter="__",
        extra="forbid",
    )

    netbox: NetBoxSettings
    fortigate: FortiGateSettings = Field(default_factory=FortiGateSettings)
    discovery: DiscoverySettings = Field(default_factory=DiscoverySettings)
    sync: SyncSettings = Field(default_factory=SyncSettings)
    fortigate_device: FortiGateDeviceSettings = Field(default_factory=FortiGateDeviceSettings)
    fortigate_network: FortiGateNetworkSettings = Field(default_factory=FortiGateNetworkSettings)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        sources: list[PydanticBaseSettingsSource] = [init_settings, env_settings, dotenv_settings]
        yaml_path = _yaml_path.get()
        if yaml_path is not None:
            sources.append(YamlConfigSettingsSource(settings_cls, yaml_file=yaml_path))
        return tuple(sources)


def resolve_config_path(config_path: str | Path | None) -> Path:
    raw = config_path or os.environ.get("NBD_CONFIG") or DEFAULT_CONFIG_PATH
    return Path(raw)


def _warn_if_world_readable(path: Path) -> None:
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        log.warning(
            "%s is accessible by group/others (mode %o); run: chmod 600 %s",
            path,
            stat.S_IMODE(mode),
            path,
        )


def _apply_legacy_env() -> None:
    for new, old in LEGACY_TOKEN_ENV.items():
        if new not in os.environ and old in os.environ:
            log.warning("Environment variable %s is deprecated, use %s", old, new)
            os.environ[new] = os.environ[old]


def load_settings(
    config_path: str | Path | None = None,
    env_file: str | Path | None = DEFAULT_ENV_FILE,
) -> Settings:
    """Load settings from YAML + .env + environment. Raises ConfigError on problems."""
    path = resolve_config_path(config_path)
    if not path.is_file():
        raise ConfigError(f"Config file not found: {path} (copy config/config.example.yaml)")

    env_path = Path(env_file) if env_file else None
    if env_path is not None and env_path.is_file():
        _warn_if_world_readable(env_path)
    else:
        env_path = None

    _apply_legacy_env()

    ctx_token = _yaml_path.set(path)
    try:
        kwargs: dict[str, Any] = {"_env_file": env_path}
        return Settings(**kwargs)
    except Exception as exc:  # pydantic.ValidationError, yaml errors
        raise ConfigError(f"Invalid configuration ({path}):\n{exc}") from exc
    finally:
        _yaml_path.reset(ctx_token)


def require_token(token: SecretStr | None, name: str) -> str:
    """Return the secret value or raise a readable ConfigError."""
    if token is None or not token.get_secret_value().strip():
        env = f"NBD_{name.upper()}__TOKEN"
        raise ConfigError(f"Missing {name} API token - set {env} in the environment or .env")
    return token.get_secret_value()


def requests_verify(verify: bool | Path, target: str) -> bool | str:
    """Translate the ``verify`` setting into a value for requests, warning when TLS is off."""
    if verify is False:
        log.warning(
            "TLS certificate verification is DISABLED for %s - API tokens can be intercepted "
            "(MITM). Set 'verify' to true or to the path of your CA bundle.",
            target,
        )
        return False
    if verify is True:
        return True
    return str(verify)
