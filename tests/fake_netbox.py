"""Tiny in-memory stand-in for the pynetbox API, enough for idempotency tests."""

from __future__ import annotations

from typing import Any

FILTER_FIELDS = {
    "device_id": "device",
    "group_id": "group",
    "interface_id": "assigned_object_id",
}


class FakeRecord:
    def __init__(self, endpoint: FakeEndpoint, rid: int, data: dict[str, Any]) -> None:
        self._endpoint = endpoint
        self.id = rid
        self.custom_fields: dict[str, Any] = {}
        for key, value in data.items():
            setattr(self, key, value)

    def __getattr__(self, name: str) -> Any:  # unknown fields are empty, like NetBox nulls
        if name.startswith("_"):
            raise AttributeError(name)
        return None

    def update(self, data: dict[str, Any]) -> bool:
        self._endpoint.updates.append((self.id, data))
        for key, value in data.items():
            if key == "custom_fields":
                self.custom_fields.update(value)
            else:
                setattr(self, key, value)
        return True


def _host(value: Any) -> str:
    return str(value).split("/")[0]


class FakeEndpoint:
    def __init__(self, tags: FakeEndpoint | None = None) -> None:
        self.tags_endpoint = tags  # used to validate tag references like NetBox does
        self.records: list[FakeRecord] = []
        self.created: list[dict[str, Any]] = []
        self.updates: list[tuple[int, dict[str, Any]]] = []

    def add(self, **data: Any) -> FakeRecord:
        record = FakeRecord(self, 1000 + len(self.records), data)
        self.records.append(record)
        return record

    def create(self, data: dict[str, Any]) -> FakeRecord:
        if self.tags_endpoint is not None:
            for ref in data.get("tags", []):
                if not self.tags_endpoint.filter(**ref):
                    raise RuntimeError(f"400 Bad Request: tags: Related object not found {ref}")
        self.created.append(data)
        return self.add(**data)

    def _match(self, record: FakeRecord, key: str, value: Any) -> bool:
        if key == "vrf_id" and value == "null":
            return getattr(record, "vrf", None) is None
        if key in ("address", "start_address", "end_address"):
            return _host(getattr(record, key)) == _host(value)
        return getattr(record, FILTER_FIELDS.get(key, key)) == value

    def filter(self, **kwargs: Any) -> list[FakeRecord]:
        return [r for r in self.records if all(self._match(r, k, v) for k, v in kwargs.items())]

    def get(self, *args: Any, **kwargs: Any) -> FakeRecord | None:
        if args:
            kwargs = {"id": args[0]}
        found = self.filter(**kwargs)
        if len(found) > 1:
            raise ValueError("get() returned more than one result")
        return found[0] if found else None


class _App:
    def __init__(self, *names: str, tags: FakeEndpoint | None = None) -> None:
        for name in names:
            setattr(self, name, FakeEndpoint(tags))


class FakeNetBox:
    def __init__(self) -> None:
        self.extras = _App("tags", "journal_entries")
        tags = self.extras.tags
        self.dcim = _App("platforms", "devices", "sites", "interfaces", "mac_addresses", tags=tags)
        self.ipam = _App("vlan_groups", "vlans", "prefixes", "ip_addresses", "ip_ranges", tags=tags)

    def endpoints(self) -> list[FakeEndpoint]:
        return [
            ep
            for app in (self.dcim, self.ipam, self.extras)
            for ep in vars(app).values()
            if isinstance(ep, FakeEndpoint)
        ]

    def total_created(self) -> int:
        return sum(len(ep.created) for ep in self.endpoints())

    def total_updates(self) -> int:
        return sum(len(ep.updates) for ep in self.endpoints())
