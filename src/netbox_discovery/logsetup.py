"""Logging setup and helpers for masking sensitive values."""

from __future__ import annotations

import logging

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"


def setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, format=LOG_FORMAT)
    # pynetbox / urllib3 debug logs may contain request headers (API tokens).
    for noisy in ("urllib3", "requests", "pynetbox"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def mask(value: str | None, keep: int = 4) -> str:
    """Mask an identifier (e.g. serial number), keeping only the last ``keep`` characters."""
    if not value:
        return "<empty>"
    if len(value) <= keep:
        return "*" * len(value)
    return "*" * (len(value) - keep) + value[-keep:]
