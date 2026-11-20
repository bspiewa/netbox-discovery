# netbox-discovery

Small, safety-first tooling that discovers what is on your network and records it in
[NetBox](https://github.com/netbox-community/netbox):

| Command | What it does | Writes to NetBox |
|---|---|---|
| `scan` | `nmap -sn` ping scan of configured networks → creates missing **IP addresses** | only with `--apply` |
| `fortigate-device` | reads hostname / model / serial from a **FortiGate** → creates the **device** (plus role and device type if missing) | only with `--apply` |
| `fortigate-network` | FortiGate **interfaces** (LAG, VLAN parents, MACs, speed), **VLANs**, **prefixes**, interface **IPs** + primary IP, **platform**, **DHCP pools** (IP ranges), **reservations** and opt-in **leases** | only with `--apply` |
| `fortigate-status` | shows FortiGate identity and DHCP servers | never |
| `fortigate-dhcp-report` | summarizes FortiGate DHCP leases (per interface, status, data quality) | never |

Design principles:

- **Dry-run by default.** Nothing is written unless `--apply` is passed; the plan is always logged first.
- **Never overwrites or deletes existing objects.** Missing objects are created; on existing
  objects only *empty* fields may be filled in (e.g. a prefix without a VLAN, a device without a platform).
- **Everything it creates is tagged** `netbox-discovery` (configurable), so managed objects are easy to find, review or clean up.
- **Secrets stay out of config files and logs.** Tokens come from the environment / `.env`; serial numbers are masked in output.

## Requirements

- Linux host with network reachability to the scanned networks, NetBox and FortiGate
- [uv](https://docs.astral.sh/uv/) (it installs a suitable Python ≥ 3.12 automatically)
- `nmap` (for `scan`), e.g. `apt install nmap`
- NetBox 4.x API token, FortiOS 7.x REST API token

## Installation

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh   # once
git clone https://github.com/<you>/netbox-discovery.git
cd netbox-discovery
uv sync                                            # creates .venv from uv.lock
cp config/config.example.yaml config/config.yaml
cp .env.example .env && chmod 600 .env             # put tokens here
```

## Configuration

Settings are read from (highest priority first): **environment variables → `.env` → YAML file → defaults**.

- YAML file: `--config PATH`, or `$NBD_CONFIG`, or `config/config.yaml`. See
  [`config/config.example.yaml`](config/config.example.yaml) for all keys. Unknown keys are rejected.
- Any key can be overridden from the environment with the `NBD_` prefix and `__` as the nesting
  separator, e.g. `NBD_NETBOX__URL`, `NBD_FORTIGATE__VDOM`.
- **Tokens only via environment / `.env`:** `NBD_NETBOX__TOKEN`, `NBD_FORTIGATE__TOKEN`
  (the old names `NETBOX_TOKEN` / `FORTIGATE_TOKEN` still work but are deprecated).

### TLS

`verify` accepts `true`, `false`, or a path to a CA bundle (PEM). With self-signed/internal
certificates, prefer pointing `verify` at your internal CA instead of disabling verification:

```yaml
netbox:
  verify: /etc/ssl/certs/internal-ca.pem
```

`verify: false` works but logs a warning on every run - API tokens are sent in clear to anyone
able to intercept the connection.

### Least-privilege tokens

- **NetBox:** create a dedicated user/token for this tool with an expiry date and object
  permissions limited to what it needs: `view` on `dcim.site`, `dcim.manufacturer`,
  `ipam.prefix`; `view` + `add` on `ipam.ipaddress`, `dcim.device`, `dcim.devicerole`,
  `dcim.devicetype`, `extras.tag`. For `fortigate-network` additionally `view` + `add` +
  `change` on `dcim.device`, `dcim.interface`, `dcim.macaddress`, `dcim.platform`,
  `ipam.vlangroup`, `ipam.vlan`, `ipam.prefix`, `ipam.ipaddress`, `ipam.iprange` and `add` on
  `extras.journalentry` (`change` is used only to fill empty fields). No `delete` is required.
- **FortiGate:** create a REST API admin with a **read-only** admin profile and restrict
  *Trusted Hosts* to the address of the machine running this tool.

## Usage

```bash
uv run netbox-discovery --help

uv run netbox-discovery scan                    # dry-run: shows which IPs would be created
uv run netbox-discovery scan --apply            # create missing IPs

uv run netbox-discovery fortigate-status
uv run netbox-discovery fortigate-dhcp-report --limit 20
uv run netbox-discovery fortigate-device        # dry-run plan
uv run netbox-discovery fortigate-device --apply
uv run netbox-discovery fortigate-network       # needs the device in NetBox (fortigate-device)
uv run netbox-discovery -v fortigate-network    # dry-run incl. every planned payload
uv run netbox-discovery fortigate-network --apply
```

`fortigate-network` notes:

- FortiOS internal interfaces (`naf.root`, `l2t.root`, `ssl.root`, `wqt*`) are skipped by default
  (`fortigate_network.exclude_interfaces`).
- VLANs go to a VLAN group scoped to the device's site (`<site>-vlans`); a VLAN ID used by two
  FortiGate interfaces is created once and reported as `skipped_duplicate`.
- The interface holding the `fortigate.url` address becomes the device primary IPv4 (if empty).
- To record the FortiOS version, create a text custom field `firmware_version` on `dcim.device`;
  version changes are then also logged as journal entries on the device.

Exit codes: `0` success, `1` runtime error (e.g. some hosts failed), `2` configuration error.

IP addresses are created with the mask of the most specific NetBox prefix that contains them
(or `/32` / `/128` if there is none), so create your prefixes first.

### Running periodically (systemd)

```ini
# /etc/systemd/system/netbox-discovery.service
[Service]
Type=oneshot
User=netbox-discovery
WorkingDirectory=/opt/netbox-discovery
ExecStart=/usr/local/bin/uv run --frozen netbox-discovery scan --apply

# /etc/systemd/system/netbox-discovery.timer
[Timer]
OnCalendar=hourly
Persistent=true
[Install]
WantedBy=timers.target
```

`systemctl enable --now netbox-discovery.timer`

## Development

```bash
uv sync                      # includes dev dependencies
uv run pytest --cov          # unit tests, no network access needed
uv run ruff check . && uv run ruff format .
uv run mypy
uv run pre-commit install    # ruff + gitleaks on every commit
```

Layout:

```
src/netbox_discovery/
  config.py            settings (YAML + env + .env), validation
  netbox_client.py     pynetbox factory, idempotent create helpers
  sources/nmap.py      nmap runner + XML parser
  sources/fortigate.py read-only FortiOS REST client + parsers
  sync/ip_sync.py      scan -> IP addresses
  sync/fortigate_device.py  FortiGate -> device (discover / plan / apply)
  sync/fortigate_network.py FortiGate -> interfaces, VLANs, prefixes, IPs, DHCP
  cli.py               command line entry point
tests/                 pytest, fixtures use RFC 5737 documentation addresses
```

Dependencies are managed with uv only: `uv add <pkg>` / `uv add --dev <pkg>`; commit `uv.lock`.

## Roadmap

- FortiGate VDOMs as virtual device contexts, HA peer, SFP transceivers as modules
- Managed FortiSwitch / FortiAP devices, SSIDs as wireless LANs, LLDP → cables
- IPsec tunnels and IKE/IPsec proposals/policies (NetBox VPN module), VIPs with NAT relations
- Reporting/cleanup of stale objects carrying the `netbox-discovery` tag
- Evaluate [NetBox Discovery (orb-agent + Diode)](https://netboxlabs.com/docs/discovery/) as a replacement for the nmap part

## Related projects

- [bl4ko/netbox-ssot](https://github.com/bl4ko/netbox-ssot) - Go, multi-source (incl. FortiGate) sync with tag-based ownership
- [bb-Ricardo/netbox-sync](https://github.com/bb-Ricardo/netbox-sync) - multi-source sync (VMware, check-mk, …)
- [NetBox Discovery / orb-agent](https://netboxlabs.com/docs/discovery/) - official network discovery via Diode

## License

MIT
