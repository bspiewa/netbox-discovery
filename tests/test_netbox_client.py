from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from pydantic import SecretStr

from netbox_discovery.config import ConfigError, NetBoxSettings
from netbox_discovery.netbox_client import (
    IpResult,
    NetBoxError,
    build_api,
    create_and_verify,
    describe_api_error,
    ensure_tag,
    upsert_ip,
)
from tests.conftest import record


def test_build_api_requires_token() -> None:
    with pytest.raises(ConfigError):
        build_api(NetBoxSettings(url="https://nb.example.com"))


def test_build_api_sets_verify() -> None:
    api = build_api(
        NetBoxSettings(url="https://nb.example.com", token=SecretStr("t"), verify=False)
    )
    assert api.http_session.verify is False


def test_upsert_ip_existing_is_noop(nb: MagicMock) -> None:
    nb.ipam.ip_addresses.filter.return_value = [record(id=1)]
    assert upsert_ip(nb, "192.0.2.1", dry_run=False) is IpResult.EXISTS
    nb.ipam.ip_addresses.create.assert_not_called()


def test_upsert_ip_dry_run_does_not_write(nb: MagicMock) -> None:
    assert upsert_ip(nb, "192.0.2.1", dry_run=True) is IpResult.WOULD_CREATE
    nb.ipam.ip_addresses.create.assert_not_called()


def test_upsert_ip_uses_prefix_mask_and_tag(nb: MagicMock) -> None:
    nb.ipam.prefixes.filter.return_value = [
        record(prefix="192.0.2.0/16"),
        record(prefix="192.0.2.0/24"),
    ]
    result = upsert_ip(nb, "192.0.2.7", dry_run=False, description="d", tag="netbox-discovery")
    assert result is IpResult.CREATED
    payload = nb.ipam.ip_addresses.create.call_args.args[0]
    assert payload["address"] == "192.0.2.7/24"
    assert payload["tags"] == [{"slug": "netbox-discovery"}]


def test_upsert_ip_host_mask_without_prefix(nb: MagicMock) -> None:
    upsert_ip(nb, "2001:db8::1", dry_run=False)
    assert nb.ipam.ip_addresses.create.call_args.args[0]["address"] == "2001:db8::1/128"


def test_upsert_ip_create_error(nb: MagicMock) -> None:
    nb.ipam.ip_addresses.create.side_effect = RuntimeError("boom")
    with pytest.raises(NetBoxError, match=r"192\.0\.2\.1/32"):
        upsert_ip(nb, "192.0.2.1", dry_run=False)


def test_create_and_verify_ok() -> None:
    ep = MagicMock()
    ep.create.return_value = record(id=5)
    ep.get.return_value = record(id=5)
    assert create_and_verify(ep, {"slug": "x"}, {"slug": "x"}, "Thing").id == 5


@pytest.mark.parametrize(
    ("created", "found"),
    [(record(id=None), None), (record(id=5), None), (record(id=5), record(id=6))],
)
def test_create_and_verify_failures(created: object, found: object) -> None:
    ep = MagicMock()
    ep.create.return_value = created
    ep.get.return_value = found
    with pytest.raises(NetBoxError):
        create_and_verify(ep, {}, {"slug": "x"}, "Thing")


def test_create_and_verify_api_error() -> None:
    ep = MagicMock()
    ep.create.side_effect = RuntimeError("denied")
    with pytest.raises(NetBoxError, match="denied"):
        create_and_verify(ep, {}, {}, "Thing")


def test_describe_api_error_truncates() -> None:
    exc = RuntimeError("bad")
    exc.error = "x" * 2000  # type: ignore[attr-defined]
    exc.req = record(status_code=400)  # type: ignore[attr-defined]
    text = describe_api_error(exc)
    assert "HTTP status: 400" in text
    assert len(text) < 600


def test_ensure_tag(nb: MagicMock) -> None:
    ensure_tag(nb, "t", dry_run=True)
    nb.extras.tags.create.assert_not_called()
    nb.extras.tags.create.return_value = record(id=1)
    nb.extras.tags.get.side_effect = [None, record(id=1)]
    ensure_tag(nb, "t", dry_run=False)
    nb.extras.tags.create.assert_called_once()
