"""
Device identity management for the ThreatGuard Windows Endpoint Agent.

Generates a stable, hardware-derived device ID and caches it on disk so
the same ID is returned across agent restarts.
"""
from __future__ import annotations

import hashlib
import platform
import uuid
from pathlib import Path


_CACHE_DIR = Path.home() / ".threatguard"
_CACHE_FILE = _CACHE_DIR / "device_id"


def _compute_device_id() -> str:
    """Derive a deterministic device ID from hardware identifiers."""
    raw = "".join([
        platform.node(),
        platform.machine(),
        platform.processor(),
        str(uuid.getnode()),
    ])
    digest = hashlib.sha256(raw.encode()).hexdigest()
    return f"WIN-{digest[:16].upper()}"


def get_device_id() -> str:
    """
    Return the stable device ID for this endpoint.

    On first call the ID is computed from hardware attributes and written to
    ``~/.threatguard/device_id``.  Subsequent calls read from that cache so
    the ID survives reboots and agent upgrades.
    """
    if _CACHE_FILE.exists():
        cached = _CACHE_FILE.read_text(encoding="utf-8").strip()
        if cached:
            return cached

    device_id = _compute_device_id()
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    _CACHE_FILE.write_text(device_id, encoding="utf-8")
    return device_id
