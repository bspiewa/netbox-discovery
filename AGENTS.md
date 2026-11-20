# Rules for AI coding agents

This repository talks to production network infrastructure (NetBox, FortiGate, nmap scans).
Follow these rules in addition to normal good practice.

## Safety - never without explicit human approval
- Do **not** run `netbox-discovery ... --apply`, or anything else that writes to NetBox.
- Do **not** run `netbox-discovery scan` or `nmap` against real networks.
- Do **not** call the real FortiGate / NetBox APIs (read-only commands included) unless asked.
- Do **not** add update/delete operations on existing NetBox objects; the tool only creates
  missing objects. Any future change/delete logic must be limited to objects carrying the
  `sync.tag` tag and must be dry-run by default.

## Secrets and private data (this is a public repository)
- Never commit `config/config.yaml`, `.env`, certificates/keys, or real tokens. They are in `.gitignore`; do not weaken it.
- Never print or log tokens; mask serial numbers with `logsetup.mask()`.
- Example data, fixtures and docs use **only** documentation ranges: `192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`, and `example.com`.
  Never copy real addresses, hostnames, site names or serials from a local config or output.
- Keep `verify: true` in examples and defaults; never silence TLS warnings globally.

## Tooling
- Dependencies: `uv add <pkg>` / `uv add --dev <pkg>` - never `pip install`, never edit `uv.lock` by hand.
- Before finishing a task, all of these must pass:
  ```bash
  uv run ruff format . && uv run ruff check . && uv run mypy && uv run pytest --cov
  ```

## Code conventions
- Python ≥ 3.12, full type hints (mypy strict), ruff rules from `pyproject.toml`.
- No side effects at import time (no config loading, API clients or network calls in module scope).
- Configuration only through `netbox_discovery.config` (pydantic models, `extra="forbid"`); add new
  keys to `config/config.example.yaml` and the README too.
- Use `logging` (module-level `log = logging.getLogger(__name__)`); `print` only for CLI report output.
- Keep parsing pure (functions taking dicts/strings) and inject clients/runners so they can be mocked.
- Every new behaviour needs unit tests in `tests/`; tests must not touch the network
  (use `responses` for HTTP, `MagicMock` for pynetbox, a fake runner for nmap).
- Raise `ConfigError` for configuration problems (CLI exit 2) and a domain error
  (`NetBoxError`, `FortiGateError`, `NmapError`, `SyncError`) for runtime failures (exit 1).
