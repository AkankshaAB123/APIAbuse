"""Thread-safe In-Memory Enforcement State Table.

Tracks source IP enforcement states (ALLOW, RATE_LIMIT, BLOCK, QUARANTINE, etc.)
with monotonic TTL expiry and sliding-window rate tracking.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import threading
import time
from typing import Optional


@dataclass
class HostEnforcementState:
    source_ip: str
    action: str  # ALLOW, MONITOR, RATE_LIMIT, BLOCK, QUARANTINE, TRANSACTION_BLOCK, URL_BLOCK
    expires_at: float  # monotonic timestamp
    reason: str = ""
    event_id: str = ""
    risk_score: float = 0.0
    risk_level: str = "LOW"
    # Sliding window timestamps for rate limiting enforcement
    request_timestamps: list[float] = field(default_factory=list)

    def is_expired(self, now: Optional[float] = None) -> bool:
        current_time = now if now is not None else time.monotonic()
        return current_time >= self.expires_at


class EnforcementTable:
    """Thread-safe storage for active network mitigation states."""

    # Default TTL in seconds for demo enforcement
    DEFAULT_TTLS: dict[str, float] = {
        "BLOCK": 60.0,
        "QUARANTINE": 60.0,
        "TRANSACTION_BLOCK": 60.0,
        "URL_BLOCK": 60.0,
        "RATE_LIMIT": 30.0,
        "MONITOR": 15.0,
        "ALLOW": 0.0,
    }

    def __init__(
        self,
        default_ttls: Optional[dict[str, float]] = None,
        rate_limit_max_requests: int = 5,
        rate_limit_window_seconds: float = 10.0,
    ) -> None:
        self._lock = threading.RLock()
        self._table: dict[str, HostEnforcementState] = {}
        self.ttls = dict(self.DEFAULT_TTLS)
        if default_ttls:
            self.ttls.update(default_ttls)
        self.rate_limit_max_requests = rate_limit_max_requests
        self.rate_limit_window_seconds = rate_limit_window_seconds

    def update_state(
        self,
        source_ip: str,
        action: str,
        reason: str = "",
        event_id: str = "",
        risk_score: float = 0.0,
        risk_level: str = "LOW",
        ttl_seconds: Optional[float] = None,
    ) -> HostEnforcementState:
        """Update or set the mitigation state for a given source IP."""
        with self._lock:
            if ttl_seconds is None:
                ttl_seconds = self.ttls.get(action.upper(), 30.0)

            now = time.monotonic()
            expires_at = now + ttl_seconds

            existing = self._table.get(source_ip)
            request_timestamps = existing.request_timestamps if existing else []

            state = HostEnforcementState(
                source_ip=source_ip,
                action=action.upper(),
                expires_at=expires_at,
                reason=reason,
                event_id=event_id,
                risk_score=risk_score,
                risk_level=risk_level,
                request_timestamps=request_timestamps,
            )
            self._table[source_ip] = state
            return state

    def get_state(self, source_ip: str) -> Optional[HostEnforcementState]:
        """Retrieve active state for source IP, pruning if expired."""
        with self._lock:
            state = self._table.get(source_ip)
            if state is None:
                return None

            now = time.monotonic()
            if state.is_expired(now):
                del self._table[source_ip]
                return None

            return state

    def check_rate_limit(self, source_ip: str) -> tuple[bool, int]:
        """Check if source IP has exceeded rate limit window under RATE_LIMIT action.

        Returns: (is_exceeded, current_request_count)
        """
        with self._lock:
            state = self.get_state(source_ip)
            if state is None or state.action != "RATE_LIMIT":
                return False, 0

            now = time.monotonic()
            cutoff = now - self.rate_limit_window_seconds
            # Filter timestamps to window
            state.request_timestamps = [t for t in state.request_timestamps if t > cutoff]
            state.request_timestamps.append(now)

            count = len(state.request_timestamps)
            return count > self.rate_limit_max_requests, count

    def clear_ip(self, source_ip: str) -> None:
        """Clear state for a specific IP."""
        with self._lock:
            self._table.pop(source_ip, None)

    def reset_all(self) -> None:
        """Reset all active enforcement states."""
        with self._lock:
            self._table.clear()

    def list_active_states(self) -> dict[str, dict]:
        """Return snapshot of active unexpired states."""
        with self._lock:
            now = time.monotonic()
            result = {}
            for ip, s in list(self._table.items()):
                if s.is_expired(now):
                    del self._table[ip]
                else:
                    result[ip] = {
                        "source_ip": s.source_ip,
                        "action": s.action,
                        "remaining_ttl_seconds": round(max(0.0, s.expires_at - now), 2),
                        "reason": s.reason,
                        "event_id": s.event_id,
                        "risk_score": s.risk_score,
                        "risk_level": s.risk_level,
                    }
            return result
