"""Shared HTTP client for Device Agents.

Provides a lightweight, resilient transport layer for transmitting
ApiSecurityEvent-compatible payloads to the central FastAPI backend.
"""

from datetime import date, datetime
import json
import logging
import os
import socket
from typing import Any, Dict, Optional, Union
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger("agents.agent_client")


class AgentResponse:
    """Structured response returned by AgentClient.send_event."""

    def __init__(
        self,
        success: bool,
        status_code: Optional[int] = None,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        raw_response: Optional[str] = None,
    ) -> None:
        self.success = success
        self.status_code = status_code
        self.data = data if data is not None else {}
        self.error = error
        self.raw_response = raw_response

    def __bool__(self) -> bool:
        return self.success

    def __getitem__(self, item: str) -> Any:
        if item in ("success", "status_code", "data", "error", "raw_response"):
            return getattr(self, item)
        if isinstance(self.data, dict) and item in self.data:
            return self.data[item]
        raise KeyError(item)

    def get(self, item: str, default: Any = None) -> Any:
        try:
            return self[item]
        except KeyError:
            return default

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "status_code": self.status_code,
            "data": self.data,
            "error": self.error,
            "raw_response": self.raw_response,
        }

    def __repr__(self) -> str:
        return (
            f"AgentResponse(success={self.success}, "
            f"status_code={self.status_code}, "
            f"error={self.error!r})"
        )


class AgentClient:
    """Reusable transport client for transmitting security telemetry events."""

    DEFAULT_ENDPOINT: str = "http://localhost:8000/events"

    def __init__(
        self,
        endpoint_url: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 10.0,
    ) -> None:
        raw_url = (
            endpoint_url
            or base_url
            or os.getenv("API_BACKEND_URL")
            or os.getenv("BACKEND_URL")
            or self.DEFAULT_ENDPOINT
        )
        self.endpoint_url: str = self._normalize_endpoint(raw_url)
        self.timeout: float = float(timeout)

    @classmethod
    def _normalize_endpoint(cls, raw_url: str) -> str:
        url = str(raw_url).strip()
        if not url:
            return cls.DEFAULT_ENDPOINT
        if "://" not in url:
            url = f"http://{url}"
        parsed = urllib.parse.urlsplit(url)
        if not parsed.path or parsed.path == "/":
            return f"{parsed.scheme}://{parsed.netloc}/events"
        return url

    def _serialize_event(self, event: Any) -> bytes:
        if hasattr(event, "model_dump"):
            payload = event.model_dump(mode="json")
        elif hasattr(event, "dict"):
            payload = event.dict()
        elif isinstance(event, dict):
            payload = event
        else:
            raise TypeError(
                f"Unsupported event type: expected Pydantic model or dict, got {type(event).__name__}"
            )

        def _json_default(obj: Any) -> Any:
            if isinstance(obj, (datetime, date)):
                return obj.isoformat()
            if hasattr(obj, "model_dump"):
                return obj.model_dump(mode="json")
            if hasattr(obj, "dict"):
                return obj.dict()
            raise TypeError(
                f"Object of type {type(obj).__name__} is not JSON serializable"
            )

        return json.dumps(payload, default=_json_default).encode("utf-8")

    def send_event(self, event: Union[Any, Dict[str, Any]]) -> AgentResponse:
        """Serialize and send an ApiSecurityEvent or dict payload to the backend /events endpoint."""
        try:
            payload_bytes = self._serialize_event(event)
        except Exception as exc:
            err_msg = f"Event serialization failed: {exc}"
            logger.error(err_msg)
            return AgentResponse(success=False, status_code=None, error=err_msg)

        req = urllib.request.Request(
            url=self.endpoint_url,
            data=payload_bytes,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status_code = getattr(resp, "status", getattr(resp, "code", 200))
                raw_body = resp.read().decode("utf-8", errors="replace")

                try:
                    data = json.loads(raw_body) if raw_body else {}
                except json.JSONDecodeError as json_err:
                    err_msg = f"Malformed JSON response from {self.endpoint_url}: {json_err}"
                    logger.error("%s (raw: %s)", err_msg, raw_body[:200])
                    return AgentResponse(
                        success=False,
                        status_code=status_code,
                        data=None,
                        error=err_msg,
                        raw_response=raw_body,
                    )

                success = 200 <= status_code < 300
                return AgentResponse(
                    success=success,
                    status_code=status_code,
                    data=data,
                    error=None if success else f"Unexpected HTTP status {status_code}",
                    raw_response=raw_body,
                )

        except urllib.error.HTTPError as http_err:
            status_code = http_err.code
            raw_body = ""
            data = None
            try:
                raw_body = http_err.read().decode("utf-8", errors="replace")
                if raw_body:
                    try:
                        data = json.loads(raw_body)
                    except Exception:
                        data = {"detail": raw_body}
            except Exception:
                pass

            err_msg = f"HTTP {status_code} error from {self.endpoint_url}: {http_err.reason}"
            logger.error("%s (response: %s)", err_msg, raw_body[:200] if raw_body else "none")
            return AgentResponse(
                success=False,
                status_code=status_code,
                data=data,
                error=err_msg,
                raw_response=raw_body,
            )

        except urllib.error.URLError as url_err:
            reason = getattr(url_err, "reason", url_err)
            if isinstance(reason, (socket.timeout, TimeoutError)) or "timed out" in str(reason).lower():
                err_msg = f"Request timed out connecting to {self.endpoint_url}: {reason}"
                logger.error(err_msg)
                return AgentResponse(success=False, status_code=None, error=err_msg)

            err_msg = f"Transport/connection error to {self.endpoint_url}: {reason}"
            logger.error(err_msg)
            return AgentResponse(success=False, status_code=None, error=err_msg)

        except (socket.timeout, TimeoutError) as timeout_err:
            err_msg = f"Request timed out after {self.timeout}s to {self.endpoint_url}: {timeout_err}"
            logger.error(err_msg)
            return AgentResponse(success=False, status_code=None, error=err_msg)

        except Exception as general_err:
            err_msg = f"Unexpected error sending event to {self.endpoint_url}: {general_err}"
            logger.exception(err_msg)
            return AgentResponse(success=False, status_code=None, error=err_msg)
