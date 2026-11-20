from __future__ import annotations

import logging
from pathlib import Path

import pytest
from pydantic import SecretStr

from netbox_discovery.config import ConfigError, load_settings, requests_verify, require_token


def test_load_yaml(config_file: Path) -> None:
    s = load_settings(config_file, env_file=None)
    assert str(s.netbox.url).startswith("https://netbox.example.com")
    assert s.netbox.verify is True
    assert [str(n) for n in s.discovery.networks] == ["192.0.2.0/24"]
    assert s.netbox.token is None


def test_env_overrides_yaml_and_provides_token(
    config_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NBD_NETBOX__TOKEN", "secret-token")
    monkeypatch.setenv("NBD_FORTIGATE__VDOM", "customer1")
    s = load_settings(config_file, env_file=None)
    assert s.netbox.token is not None
    assert s.netbox.token.get_secret_value() == "secret-token"
    assert s.fortigate.vdom == "customer1"
    assert "secret-token" not in repr(s)


def test_dotenv_file(config_file: Path, tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("NBD_FORTIGATE__TOKEN=from-dotenv\n")
    env.chmod(0o600)
    s = load_settings(config_file, env_file=env)
    assert s.fortigate.token is not None
    assert s.fortigate.token.get_secret_value() == "from-dotenv"


def test_dotenv_permissions_warning(
    config_file: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    env = tmp_path / ".env"
    env.write_text("NBD_NETBOX__TOKEN=x\n")
    env.chmod(0o644)
    load_settings(config_file, env_file=env)
    assert "chmod 600" in caplog.text


def test_legacy_token_env(config_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NETBOX_TOKEN", "legacy")
    s = load_settings(config_file, env_file=None)
    assert s.netbox.token is not None
    assert s.netbox.token.get_secret_value() == "legacy"


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_settings(tmp_path / "nope.yaml", env_file=None)


@pytest.mark.parametrize(
    "networks",
    ['["192.0.2.5/24"]', '["-iL /etc/passwd"]', '["not-a-network"]'],
)
def test_invalid_network_rejected(tmp_path: Path, networks: str) -> None:
    path = tmp_path / "c.yaml"
    path.write_text(
        f'netbox: {{url: "https://nb.example.com"}}\ndiscovery: {{networks: {networks}}}\n'
    )
    with pytest.raises(ConfigError):
        load_settings(path, env_file=None)


def test_unknown_key_rejected(tmp_path: Path) -> None:
    path = tmp_path / "c.yaml"
    path.write_text('netbox: {url: "https://nb.example.com", verify_ssl: false}\n')
    with pytest.raises(ConfigError, match="verify_ssl"):
        load_settings(path, env_file=None)


def test_require_token() -> None:
    assert require_token(SecretStr("abc"), "netbox") == "abc"
    with pytest.raises(ConfigError, match="NBD_NETBOX__TOKEN"):
        require_token(None, "netbox")
    with pytest.raises(ConfigError):
        require_token(SecretStr("  "), "netbox")


def test_requests_verify(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    assert requests_verify(True, "x") is True
    ca = tmp_path / "ca.pem"
    assert requests_verify(ca, "x") == str(ca)
    with caplog.at_level(logging.WARNING):
        assert requests_verify(False, "NetBox") is False
    assert "DISABLED" in caplog.text
