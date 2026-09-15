"""ThreatGuard Real Enforcement Gateway Proxy.

Intercepts incoming HTTP requests, performs real source IP enforcement via
EnforcementTable, forwards requests to the protected demo target, synchronizes
security telemetry to the existing backend /events pipeline, and updates
the enforcement table with the actual mitigation decision.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import os
import time
from typing import Any, Callable, Optional
import urllib.error
import urllib.parse
import urllib.request
from uuid import uuid4

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from gateway.enforcement_table import EnforcementTable, HostEnforcementState

logger = logging.getLogger("gateway.proxy")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [GATEWAY] %(message)s")


class GatewayConfig(BaseModel):
    backend_events_url: str = "http://127.0.0.1:8000/events"
    target_base_url: str = "http://127.0.0.1:8000"
    gateway_host: str = "0.0.0.0"
    gateway_port: int = 8080
    timeout_seconds: float = 5.0
    # Custom TTL overrides (seconds)
    block_ttl_seconds: float = 60.0
    rate_limit_ttl_seconds: float = 30.0


def extract_real_source_ip(request: Request) -> str:
    """Extract the real client source IP from headers or connection.

    Prioritizes X-Forwarded-For (leftmost) if behind reverse proxy, otherwise direct socket client.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if parts:
            return parts[0]

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    if request.client and request.client.host:
        return request.client.host

    return "127.0.0.1"


def create_gateway_app(
    config: Optional[GatewayConfig] = None,
    enforcement_table: Optional[EnforcementTable] = None,
    event_submitter: Optional[Callable[[dict], dict]] = None,
    target_forwarder: Optional[Callable[[str, str, dict, bytes], tuple[int, dict, bytes]]] = None,
) -> FastAPI:
    """Create and configure the ThreatGuard Enforcement Gateway FastAPI application."""
    cfg = config or GatewayConfig(
        backend_events_url=os.getenv("BACKEND_EVENTS_URL", "http://127.0.0.1:8000/events"),
        target_base_url=os.getenv("TARGET_BASE_URL", "http://127.0.0.1:8000"),
        gateway_host=os.getenv("GATEWAY_HOST", "0.0.0.0"),
        gateway_port=int(os.getenv("GATEWAY_PORT", "8080")),
    )

    table = enforcement_table or EnforcementTable(
        default_ttls={
            "BLOCK": cfg.block_ttl_seconds,
            "RATE_LIMIT": cfg.rate_limit_ttl_seconds,
        }
    )

    app = FastAPI(
        title="ThreatGuard Enforcement Gateway",
        description="Real HTTP active defense gateway for the Intelligent Cloud IDS",
        version="1.0.0",
    )

    # Store references on app state for inspection/testing
    app.state.config = cfg
    app.state.table = table

    # -------------------------------------------------------------------------
    # Helper: Submit event to backend /events
    # -------------------------------------------------------------------------
    def _default_submit_event(event_dict: dict) -> dict:
        data = json.dumps(event_dict).encode("utf-8")
        req = urllib.request.Request(
            cfg.backend_events_url,
            data=data,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=cfg.timeout_seconds) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw)

    submit_event_fn = event_submitter or _default_submit_event

    # -------------------------------------------------------------------------
    # Helper: Forward request to protected target
    # -------------------------------------------------------------------------
    def _default_forward_target(
        method: str, path: str, headers: dict, body: bytes
    ) -> tuple[int, dict, bytes]:
        url = urllib.parse.urljoin(cfg.target_base_url, path)
        req_headers = dict(headers)
        # Remove host header to allow target host resolution
        req_headers.pop("host", None)
        req_headers.pop("Host", None)
        req = urllib.request.Request(
            url,
            data=body if method.upper() in ("POST", "PUT", "PATCH") else None,
            headers=req_headers,
            method=method.upper(),
        )
        try:
            with urllib.request.urlopen(req, timeout=cfg.timeout_seconds) as resp:
                resp_headers = dict(resp.headers)
                resp_body = resp.read()
                return resp.status, resp_headers, resp_body
        except urllib.error.HTTPError as http_err:
            return http_err.code, dict(http_err.headers), http_err.read()

    forward_target_fn = target_forwarder or _default_forward_target

    # =========================================================================
    # Administrative & State Inspection Routes
    # =========================================================================
    @app.get("/gateway/health")
    def gateway_health():
        return {
            "status": "healthy",
            "gateway": "ThreatGuard Active Defense Proxy",
            "backend_events_url": cfg.backend_events_url,
            "target_base_url": cfg.target_base_url,
        }

    @app.get("/gateway/enforcement-table")
    def get_enforcement_table():
        return {
            "active_states": table.list_active_states(),
        }

    @app.post("/gateway/reset-enforcement")
    def reset_enforcement():
        table.reset_all()
        return {"status": "reset", "message": "All active enforcement states cleared."}

    # =========================================================================
    # Gateway Interception Handler (All other paths)
    # =========================================================================
    @app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    async def proxy_handler(request: Request, full_path: str):
        source_ip = extract_real_source_ip(request)
        path = f"/{full_path}"
        method = request.method.upper()

        logger.info(f"Incoming {method} {path} from real IP: {source_ip}")

        # ---------------------------------------------------------------------
        # 1. Check existing enforcement state before reaching target
        # ---------------------------------------------------------------------
        active_state = table.get_state(source_ip)
        if active_state is not None:
            action = active_state.action

            # A. Active BLOCK / QUARANTINE
            if action in ("BLOCK", "QUARANTINE", "TRANSACTION_BLOCK", "URL_BLOCK"):
                logger.warning(
                    f"REJECTED by gateway enforcement: IP {source_ip} is currently {action}. "
                    f"Reason: {active_state.reason}. Target was NOT reached."
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "access_forbidden",
                        "status": "blocked",
                        "enforcement_action": action,
                        "reason": f"ThreatGuard Active Defense: Source IP {source_ip} is blocked.",
                        "details": active_state.reason,
                        "risk_level": active_state.risk_level,
                        "event_id": active_state.event_id,
                    },
                    headers={"X-ThreatGuard-Action": action},
                )

            # B. Active RATE_LIMIT
            if action == "RATE_LIMIT":
                exceeded, req_count = table.check_rate_limit(source_ip)
                if exceeded:
                    logger.warning(
                        f"RATE LIMITED by gateway enforcement: IP {source_ip} exceeded window limit "
                        f"({req_count} requests). Target was NOT reached."
                    )
                    return JSONResponse(
                        status_code=429,
                        content={
                            "error": "too_many_requests",
                            "status": "rate_limited",
                            "enforcement_action": "RATE_LIMIT",
                            "reason": f"ThreatGuard Active Defense: Source IP {source_ip} rate-limited.",
                            "details": f"Exceeded allowed rate ({req_count} requests).",
                            "event_id": active_state.event_id,
                        },
                        headers={"X-ThreatGuard-Action": "RATE_LIMIT"},
                    )

        # ---------------------------------------------------------------------
        # 2. Forward request to protected demo target
        # ---------------------------------------------------------------------
        body_bytes = await request.body()
        req_headers = dict(request.headers)

        try:
            target_status, target_headers, target_body = forward_target_fn(
                method, path, req_headers, body_bytes
            )
            logger.info(f"Target responded with status HTTP {target_status} for {method} {path}")
        except Exception as exc:
            logger.error(f"Protected target unreachable at {cfg.target_base_url}: {exc}")
            return JSONResponse(
                status_code=502,
                content={
                    "error": "bad_gateway",
                    "message": "Protected demo target is unreachable.",
                    "details": str(exc),
                },
            )

        # ---------------------------------------------------------------------
        # 3. Synthesize ApiSecurityEvent using existing backend contract
        # ---------------------------------------------------------------------
        parsed_body = None
        if body_bytes:
            try:
                parsed_body = json.loads(body_bytes.decode("utf-8"))
            except Exception:
                parsed_body = None

        now_iso = datetime.now(timezone.utc).isoformat()
        event_id = f"evt-gw-{uuid4().hex[:10]}"

        event_payload = {
            "schema_version": "1.0",
            "event_id": event_id,
            "timestamp": now_iso,
            "domain": "API",
            "network": {
                "source_ip": source_ip,
                "user_agent": request.headers.get("user-agent", "ThreatGuard-Gateway/1.0"),
                "destination_ip": cfg.gateway_host,
                "protocol": "HTTP",
                "connection_status": "success",
            },
            "identity": {
                "user_id": (parsed_body.get("username") if isinstance(parsed_body, dict) else None),
                "session_id": f"gw-sess-{source_ip.replace('.', '_')}",
                "roles": [],
                "is_authenticated": (target_status == 200),
            },
            "request": {
                "method": method,
                "endpoint": path,
                "headers": {k: v for k, v in request.headers.items() if k.lower() not in ("authorization", "cookie")},
                "body": parsed_body,
            },
            "response": {
                "status_code": target_status,
                "latency_ms": 10.0,
            },
            "resource": {
                "resource_type": "api_endpoint",
                "resource_id": path,
                "is_sensitive": False,
            },
        }

        # ---------------------------------------------------------------------
        # 4. Synchronously submit event to existing POST /events
        # ---------------------------------------------------------------------
        try:
            processing_result = submit_event_fn(event_payload)
            mitigation_action = processing_result.get("mitigation_action", "ALLOW").upper()
            risk_data = processing_result.get("risk_assessment") or {}
            risk_score = float(risk_data.get("risk_score", 0.0))
            risk_level = str(risk_data.get("risk_level", "LOW"))
            reasons = risk_data.get("reasons", [])
            reason_str = reasons[0] if reasons else f"Mitigation set to {mitigation_action}"

            logger.info(
                f"Backend IDS decision for {source_ip} [{event_id}]: "
                f"Action={mitigation_action}, RiskScore={risk_score}, Level={risk_level}"
            )
        except Exception as exc:
            # FAIL CLOSED for security: If IDS is configured but down, reject sensitive operations
            logger.error(f"IDS backend failed at {cfg.backend_events_url}: {exc}")
            return JSONResponse(
                status_code=503,
                content={
                    "error": "service_unavailable",
                    "status": "failed_closed",
                    "message": "ThreatGuard security verification unavailable; request failed closed.",
                    "details": str(exc),
                },
                headers={"X-ThreatGuard-Action": "FAIL_CLOSED"},
            )

        # ---------------------------------------------------------------------
        # 5. Update in-memory enforcement state based on actual mitigation_action
        # ---------------------------------------------------------------------
        if mitigation_action in ("BLOCK", "RATE_LIMIT", "QUARANTINE", "TRANSACTION_BLOCK", "URL_BLOCK"):
            table.update_state(
                source_ip=source_ip,
                action=mitigation_action,
                reason=reason_str,
                event_id=event_id,
                risk_score=risk_score,
                risk_level=risk_level,
            )
            logger.warning(
                f"Updated gateway enforcement state: IP {source_ip} -> {mitigation_action} "
                f"(Score: {risk_score}, Level: {risk_level})"
            )

        # ---------------------------------------------------------------------
        # 6. Return response received from target with security headers
        # ---------------------------------------------------------------------
        # Parse JSON if possible to return clean JSONResponse
        content_type = target_headers.get("content-type", target_headers.get("Content-Type", ""))
        headers_to_return = {
            "X-ThreatGuard-Action": mitigation_action,
            "X-ThreatGuard-Event-Id": event_id,
        }

        if "application/json" in content_type:
            try:
                body_json = json.loads(target_body.decode("utf-8"))
                return JSONResponse(status_code=target_status, content=body_json, headers=headers_to_return)
            except Exception:
                pass

        return Response(content=target_body, status_code=target_status, media_type=content_type, headers=headers_to_return)

    return app


# Default ASGI entrypoint
app = create_gateway_app()
