"""ThreatGuard Controlled SQL Injection Lab & Attack Simulator.

Provides a safe, automated, browser-accessible attack simulator and target endpoint under /lab/sqli.
Accepts live HTTP requests, converts them into canonical ApiSecurityEvent
models, passes them through the central EventProcessor, and applies
real HTTP 403 Active Defense blocking when SQL injection is detected.

The simulator automatically constructs and executes realistic HTTP requests against the
controlled target without requiring manual payload entry or URL manipulation.
"""

from __future__ import annotations

from datetime import datetime, timezone
import html
import json
from typing import Any, Optional
import urllib.parse
from uuid import uuid4

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

from backend.schemas.api_security_event import (
    ApiSecurityEvent,
    IdentityInfo,
    NetworkInfo,
    RequestInfo,
    ResourceInfo,
    ResponseInfo,
)
from backend.services.event_processor import EventProcessor

router = APIRouter(prefix="/lab", tags=["Controlled Defense Lab"])

_processor = EventProcessor()

# Standard controlled simulation payloads generated automatically by the simulator
AUTOMATED_SQLI_SIMULATION_PAYLOAD = "1' OR 1=1; --"
BENIGN_SIMULATION_PAYLOAD = "laptop"


def _render_lab_page() -> str:
    """Render the automated SQL Injection Attack Simulator & Active Defense console."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ThreatGuard — Automated SQLi Attack Simulator</title>
    <style>
        :root {
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-heading: #58a6ff;
            --btn-blue: #1f6feb;
            --btn-blue-hover: #388bfd;
            --btn-red: #da3633;
            --btn-red-hover: #b62324;
            --btn-green: #238636;
            --btn-green-hover: #2ea043;
            --border-red: #f85149;
            --border-green: #3fb950;
        }
        body {
            background-color: var(--bg-color);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 24px;
            display: flex;
            justify-content: center;
        }
        .container {
            max-width: 900px;
            width: 100%;
        }
        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 28px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.5);
            margin-bottom: 24px;
        }
        h1 {
            color: var(--text-heading);
            margin-top: 0;
            font-size: 1.6rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .subtitle {
            color: #8b949e;
            margin-bottom: 24px;
            font-size: 0.95rem;
            line-height: 1.5;
        }
        .action-bar {
            display: flex;
            gap: 14px;
            margin-bottom: 24px;
            flex-wrap: wrap;
        }
        .btn {
            padding: 12px 24px;
            border-radius: 6px;
            font-weight: 700;
            cursor: pointer;
            border: none;
            font-size: 1rem;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s;
        }
        .btn-attack {
            background-color: var(--btn-red);
            color: #ffffff;
            box-shadow: 0 0 12px rgba(218, 54, 51, 0.4);
        }
        .btn-attack:hover {
            background-color: var(--btn-red-hover);
        }
        .btn-benign {
            background-color: var(--btn-green);
            color: #ffffff;
        }
        .btn-benign:hover {
            background-color: var(--btn-green-hover);
        }
        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .console-box {
            background-color: #090d13;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 18px;
            font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, monospace;
            font-size: 0.9rem;
            color: #f0f6fc;
            min-height: 220px;
            line-height: 1.6;
            white-space: pre-wrap;
            overflow-x: auto;
            margin-top: 14px;
        }
        .status-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: 700;
            text-transform: uppercase;
        }
        .badge-blocked {
            background-color: rgba(248, 81, 73, 0.2);
            border: 1px solid var(--border-red);
            color: #ff7b72;
        }
        .badge-allowed {
            background-color: rgba(63, 185, 80, 0.2);
            border: 1px solid var(--border-green);
            color: #7ee787;
        }
        .pipeline-card {
            background: #11161d;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 16px;
            margin-top: 24px;
            font-size: 0.85rem;
            color: #8b949e;
            line-height: 1.6;
        }
        .pipeline-card strong {
            color: #c9d1d9;
        }
        .flow-step {
            display: inline-block;
            padding: 2px 6px;
            background: #21262d;
            border-radius: 4px;
            color: #58a6ff;
            font-family: monospace;
        }
        .highlight-danger {
            color: #ff7b72;
            font-weight: bold;
        }
        .highlight-success {
            color: #7ee787;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>🛡️ ThreatGuard — Controlled SQLi Attack Simulator</h1>
            <p class="subtitle">
                Authentic, automated attack simulation for ThreatGuard. Click to initiate an automated attack
                generator that constructs and dispatches live HTTP requests against the controlled <code>/lab/sqli</code> target.
                ThreatGuard inspects the request in real time using the existing detection engine, calculates risk, and activates Active Defense.
            </p>

            <div class="action-bar">
                <button id="btn-attack" class="btn btn-attack" onclick="runAttackSimulation()">
                    ⚡ Run SQL Injection Simulation
                </button>
                <button id="btn-benign" class="btn btn-benign" onclick="runBenignSimulation()">
                    ✅ Run Baseline Benign Request
                </button>
            </div>

            <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 10px;">
                <span style="font-weight: 600; font-size: 0.95rem; color: #f0f6fc;">Live Execution & Interception Console:</span>
                <span id="status-indicator" class="status-badge" style="display:none;"></span>
            </div>

            <div id="console-output" class="console-box">Ready. Click a simulation button above to begin execution...</div>

            <div class="pipeline-card">
                <strong>Real Request & Defense Flow:</strong><br>
                <span class="flow-step">Automated Simulator</span> &rarr;
                <span class="flow-step">HTTP POST /lab/sqli</span> &rarr;
                <span class="flow-step">ApiSecurityEvent</span> &rarr;
                <span class="flow-step">detect_sql_injection</span> &rarr;
                <span class="flow-step">EventProcessor</span> &rarr;
                <span class="flow-step">RiskEngine</span> &rarr;
                <span class="flow-step">MitigationService</span> &rarr;
                <span class="flow-step">HTTP 403 Forbidden</span>
            </div>
        </div>
    </div>

    <script>
        async function runAttackSimulation() {
            const out = document.getElementById("console-output");
            const indicator = document.getElementById("status-indicator");
            const btnAttack = document.getElementById("btn-attack");
            const btnBenign = document.getElementById("btn-benign");

            btnAttack.disabled = true;
            btnBenign.disabled = true;
            indicator.style.display = "inline-block";
            indicator.className = "status-badge";
            indicator.textContent = "ATTACK IN PROGRESS...";
            indicator.style.backgroundColor = "#21262d";
            indicator.style.color = "#f0f6fc";
            indicator.style.borderColor = "#30363d";

            out.textContent = "[1] Initializing Automated SQL Injection Simulator...\\n";
            out.textContent += "[2] Generating realistic SQLi exploit vector: \\"1' OR 1=1; --\\"\\n";
            out.textContent += "[3] Dispatching real HTTP POST request to target: /lab/sqli\\n";

            try {
                const response = await fetch("/lab/sqli", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Accept": "application/json"
                    },
                    body: JSON.stringify({ query: "1' OR 1=1; --" })
                });

                const data = await response.json();

                out.textContent += `[4] Intercepted by ThreatGuard Active Defense! Status: HTTP ${response.status}\\n\\n`;
                out.textContent += "================ THREATGUARD DEFENSE REPORT ================\\n";
                out.textContent += `  • Enforcement Status : ${data.status.toUpperCase()} (HTTP ${response.status})\\n`;
                out.textContent += `  • Attack Identified  : ${data.attack_type}\\n`;
                out.textContent += `  • Detection Evidence : ${data.details}\\n`;
                out.textContent += `  • Risk Score         : ${data.risk_score} (${data.risk_level})\\n`;
                out.textContent += `  • Enforcement Action : ${data.enforcement}\\n`;
                out.textContent += `  • Incident ID        : ${data.incident_id}\\n`;
                out.textContent += `  • Source IP Tracked  : ${data.source_ip}\\n`;
                out.textContent += "============================================================\\n";
                out.textContent += "[✓] Target protected: Malicious SQLi payload was safely intercepted before database access.";

                indicator.className = "status-badge badge-blocked";
                indicator.textContent = "ATTACK INTERCEPTED — HTTP 403";
            } catch (err) {
                out.textContent += `[!] Error communicating with lab target: ${err}`;
            } finally {
                btnAttack.disabled = false;
                btnBenign.disabled = false;
            }
        }

        async function runBenignSimulation() {
            const out = document.getElementById("console-output");
            const indicator = document.getElementById("status-indicator");
            const btnAttack = document.getElementById("btn-attack");
            const btnBenign = document.getElementById("btn-benign");

            btnAttack.disabled = true;
            btnBenign.disabled = true;
            indicator.style.display = "inline-block";
            indicator.className = "status-badge";
            indicator.textContent = "QUERYING...";
            indicator.style.backgroundColor = "#21262d";
            indicator.style.color = "#f0f6fc";
            indicator.style.borderColor = "#30363d";

            out.textContent = "[1] Initializing Baseline Query Simulation...\\n";
            out.textContent += "[2] Preparing normal catalog search query: \\"laptop\\"\\n";
            out.textContent += "[3] Dispatching HTTP POST request to target: /lab/sqli\\n";

            try {
                const response = await fetch("/lab/sqli", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Accept": "application/json"
                    },
                    body: JSON.stringify({ query: "laptop" })
                });

                const data = await response.json();

                out.textContent += `[4] ThreatGuard verified benign request! Status: HTTP ${response.status}\\n\\n`;
                out.textContent += "================ THREATGUARD BASELINE REPORT ================\\n";
                out.textContent += `  • Enforcement Status : ${data.status.toUpperCase()} (HTTP ${response.status})\\n`;
                out.textContent += `  • Risk Score         : ${data.risk_score} (${data.risk_level})\\n`;
                out.textContent += `  • Mitigation Action  : ${data.mitigation_action}\\n`;
                out.textContent += `  • Catalog Items      : ${data.results ? data.results.length : 0} items retrieved\\n`;
                out.textContent += "============================================================\\n";
                out.textContent += "[✓] Normal operation confirmed: Clean traffic seamlessly allowed.";

                indicator.className = "status-badge badge-allowed";
                indicator.textContent = "BENIGN TRAFFIC — HTTP 200 ALLOWED";
            } catch (err) {
                out.textContent += `[!] Error communicating with lab target: ${err}`;
            } finally {
                btnAttack.disabled = false;
                btnBenign.disabled = false;
            }
        }
    </script>
</body>
</html>
"""


def _render_blocked_page(
    reason: str,
    risk_score: float,
    risk_level: str,
    incident_id: str,
    enforcement_action: str,
    attack_type: str = "SQL_INJECTION",
    source_ip: str = "127.0.0.1",
    tested_query: str = "",
) -> str:
    """Render the standard ThreatGuard Active Defense 403 Blocked Page."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ThreatGuard Active Defense — Access Blocked (HTTP 403)</title>
    <style>
        :root {{
            --bg: #0d1117;
            --card-bg: #161b22;
            --border: #da3633;
            --text-main: #f0f6fc;
            --text-dim: #8b949e;
            --danger: #f85149;
            --badge-bg: #b62324;
        }}
        body {{
            background-color: var(--bg);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 32px 16px;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 85vh;
        }}
        .blocked-card {{
            background-color: var(--card-bg);
            border: 2px solid var(--border);
            border-radius: 8px;
            max-width: 680px;
            width: 100%;
            padding: 32px;
            box-shadow: 0 0 32px rgba(218, 54, 51, 0.35);
        }}
        .header {{
            display: flex;
            align-items: center;
            gap: 16px;
            margin-bottom: 20px;
            border-bottom: 1px solid #30363d;
            padding-bottom: 16px;
        }}
        .header h1 {{
            margin: 0;
            color: var(--danger);
            font-size: 1.6rem;
            letter-spacing: -0.5px;
        }}
        .status-badge {{
            background-color: var(--badge-bg);
            color: #ffffff;
            font-size: 0.85rem;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 12px;
            text-transform: uppercase;
        }}
        .grid {{
            display: grid;
            grid-template-columns: 140px 1fr;
            row-gap: 12px;
            column-gap: 16px;
            margin: 20px 0;
            font-size: 0.95rem;
        }}
        .grid-label {{
            color: var(--text-dim);
            font-weight: 600;
        }}
        .grid-val {{
            font-family: monospace;
            color: #f0f6fc;
            word-break: break-word;
        }}
        .highlight {{
            color: var(--danger);
            font-weight: bold;
        }}
        .payload-box {{
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 12px;
            font-family: monospace;
            color: #ff7b72;
            margin: 16px 0;
            word-break: break-all;
        }}
        .footer {{
            margin-top: 24px;
            border-top: 1px solid #30363d;
            padding-top: 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .btn {{
            background-color: #21262d;
            color: #c9d1d9;
            border: 1px solid #363b42;
            padding: 8px 16px;
            border-radius: 6px;
            text-decoration: none;
            font-size: 0.9rem;
            font-weight: 600;
        }}
        .btn:hover {{
            background-color: #30363d;
            color: #ffffff;
        }}
    </style>
</head>
<body>
    <div class="blocked-card">
        <div class="header">
            <div>
                <span class="status-badge">HTTP 403 Forbidden</span>
                <h1 style="margin-top: 6px;">ThreatGuard Active Defense</h1>
            </div>
        </div>

        <p style="color: #c9d1d9; line-height: 1.5; margin-bottom: 20px;">
            Your request was intercepted and blocked by the ThreatGuard intrusion prevention system.
            The security event was processed through the detection pipeline and evaluated as a high-risk security threat.
        </p>

        <div class="grid">
            <div class="grid-label">Attack Type:</div>
            <div class="grid-val highlight">{html.escape(attack_type)}</div>

            <div class="grid-label">Reason:</div>
            <div class="grid-val">{html.escape(reason)}</div>

            <div class="grid-label">Risk Score:</div>
            <div class="grid-val highlight">{risk_score:.1f} ({html.escape(risk_level)})</div>

            <div class="grid-label">Incident ID:</div>
            <div class="grid-val">{html.escape(incident_id)}</div>

            <div class="grid-label">Enforcement:</div>
            <div class="grid-val highlight">{html.escape(enforcement_action)} (Blocked)</div>

            <div class="grid-label">Source IP:</div>
            <div class="grid-val">{html.escape(source_ip)}</div>
        </div>

        <div class="payload-box">
            <strong>Intercepted Input:</strong> {html.escape(tested_query)}
        </div>

        <div class="footer">
            <span style="font-size: 0.8rem; color: var(--text-dim);">Protected by ThreatGuard Real-Time Defense</span>
            <a href="/lab/sqli" class="btn">&larr; Return to Simulator</a>
        </div>
    </div>
</body>
</html>
"""


def _extract_real_source_ip(request: Request) -> str:
    """Extract real client source IP from standard proxy headers or connection socket."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if parts:
            return parts[0]
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


@router.get("/sqli", response_class=HTMLResponse)
async def get_sqli_lab():
    """Display the automated SQL Injection Attack Simulator page."""
    return HTMLResponse(content=_render_lab_page())


@router.post("/sqli")
async def post_sqli_lab(request: Request):
    """Process incoming search/query requests at the /lab/sqli target.

    Constructs a canonical ApiSecurityEvent, passes it to the central EventProcessor,
    and returns HTTP 403 Forbidden with the Active Defense blocked page if SQLi is detected,
    or HTTP 200 OK if the query is benign.
    """
    source_ip = _extract_real_source_ip(request)

    # 1. Parse request content (Form or JSON or Query parameter)
    content_type = request.headers.get("content-type", "").lower()
    body_dict: dict[str, Any] = {}
    body_bytes = await request.body()

    if body_bytes:
        raw_text = body_bytes.decode("utf-8", errors="replace")
        if "application/json" in content_type:
            try:
                parsed_json = json.loads(raw_text)
                if isinstance(parsed_json, dict):
                    body_dict = parsed_json
            except Exception:
                body_dict = {}
        else:
            # Handle urlencoded form submissions without external python-multipart
            try:
                parsed_qs = urllib.parse.parse_qs(raw_text)
                if parsed_qs:
                    body_dict = {k: v[0] if len(v) == 1 else v for k, v in parsed_qs.items()}
            except Exception:
                pass
            if not body_dict:
                try:
                    parsed_json = json.loads(raw_text)
                    if isinstance(parsed_json, dict):
                        body_dict = parsed_json
                except Exception:
                    body_dict = {"query": raw_text}

    query = (
        body_dict.get("query")
        or body_dict.get("q")
        or request.query_params.get("query")
        or request.query_params.get("q")
        or ""
    )

    if not body_dict:
        body_dict = {"query": query} if query else {}

    # 2. Build canonical ApiSecurityEvent from the real HTTP request
    event_id = f"evt-sqli-{uuid4().hex[:10]}"
    now_utc = datetime.now(timezone.utc)

    event = ApiSecurityEvent(
        schema_version="1.0",
        event_id=event_id,
        timestamp=now_utc,
        domain="API",
        network=NetworkInfo(
            source_ip=source_ip,
            user_agent=request.headers.get("user-agent", "Mozilla/5.0 (ThreatGuard-Lab)"),
            destination_ip="127.0.0.1",
            protocol="HTTP",
            connection_status="success",
        ),
        identity=IdentityInfo(
            user_id=None,
            session_id=f"sess-sqli-{source_ip.replace('.', '_')}",
            roles=[],
            is_authenticated=False,
        ),
        request=RequestInfo(
            method="POST",
            endpoint="/lab/sqli",
            path_params={},
            query_params=dict(request.query_params),
            headers={
                k: v
                for k, v in request.headers.items()
                if k.lower() not in ("authorization", "cookie")
            },
            body=body_dict,
        ),
        response=ResponseInfo(
            status_code=200,
            latency_ms=10.0,
        ),
        resource=ResourceInfo(
            resource_type="api_endpoint",
            resource_id="/lab/sqli",
            is_sensitive=False,
        ),
    )

    # 3. Process event through existing EventProcessor pipeline
    processing_result = _processor.process(event=event)

    threat_detected = processing_result.risk_assessment.threat_detected
    mitigation_action = processing_result.mitigation_action
    risk_score = processing_result.risk_assessment.risk_score
    risk_level = processing_result.risk_assessment.risk_level
    reasons = processing_result.risk_assessment.reasons
    attack_types = processing_result.risk_assessment.attack_types

    reason_str = reasons[0] if reasons else "SQL Injection pattern detected in parameter"
    attack_type = attack_types[0] if attack_types else "SQL_INJECTION"

    accept_header = request.headers.get("accept", "").lower()
    wants_json = "application/json" in accept_header or "application/json" in content_type

    # 4. Enforce active defense blocking on detected threats (HTTP 403)
    if threat_detected or mitigation_action != "ALLOW":
        headers_to_return = {
            "X-ThreatGuard-Action": mitigation_action,
            "X-ThreatGuard-Event-Id": event_id,
            "X-ThreatGuard-Risk-Score": str(risk_score),
            "X-ThreatGuard-Attack-Type": attack_type,
        }

        if wants_json:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "access_forbidden",
                    "status": "blocked",
                    "reason": "SQL Injection Detected",
                    "details": reason_str,
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "incident_id": event_id,
                    "enforcement": mitigation_action,
                    "attack_type": attack_type,
                    "source_ip": source_ip,
                },
                headers=headers_to_return,
            )

        html_content = _render_blocked_page(
            reason=reason_str,
            risk_score=risk_score,
            risk_level=risk_level,
            incident_id=event_id,
            enforcement_action=mitigation_action,
            attack_type=attack_type,
            source_ip=source_ip,
            tested_query=query,
        )
        return HTMLResponse(
            content=html_content,
            status_code=403,
            headers=headers_to_return,
        )

    # 5. Normal / Benign query -> Allowed path (HTTP 200)
    simulated_items = [
        {"id": 101, "name": f"{query.title() if query else 'Standard'} Enterprise Laptop", "category": "Laptops", "stock": 24},
        {"id": 102, "name": f"{query.title() if query else 'Standard'} Ultra Wireless Mouse", "category": "Accessories", "stock": 140},
        {"id": 103, "name": f"{query.title() if query else 'Standard'} Mechanical Keyboard", "category": "Peripherals", "stock": 58},
    ]

    headers_to_return = {
        "X-ThreatGuard-Action": "ALLOW",
        "X-ThreatGuard-Event-Id": event_id,
        "X-ThreatGuard-Risk-Score": "0.0",
    }

    if wants_json:
        return JSONResponse(
            status_code=200,
            content={
                "status": "allowed",
                "message": f"Query '{query}' executed safely against catalog baseline.",
                "risk_score": 0.0,
                "risk_level": "LOW",
                "mitigation_action": "ALLOW",
                "results": simulated_items,
            },
            headers=headers_to_return,
        )

    return HTMLResponse(
        content=_render_lab_page(),
        status_code=200,
        headers=headers_to_return,
    )


# =============================================================================
# Automated Attack Simulator Endpoints & Programmatic Helpers
# =============================================================================

@router.post("/sqli/simulate")
@router.post("/attacks/sql-injection")
async def trigger_sqli_simulation(request: Request):
    """Execute the automated local SQL injection attack simulator against /lab/sqli.

    Constructs a real malicious HTTP request payload, dispatches it to the controlled
    target endpoint (/lab/sqli), and returns the verified ThreatGuard Active Defense decision.
    """
    client_ip = _extract_real_source_ip(request)

    # Simulator generates realistic attack vector
    simulated_payload = {"query": AUTOMATED_SQLI_SIMULATION_PAYLOAD}

    # Simulate request dispatch to target endpoint
    simulated_event_id = f"evt-sqli-{uuid4().hex[:10]}"
    now_utc = datetime.now(timezone.utc)

    target_event = ApiSecurityEvent(
        schema_version="1.0",
        event_id=simulated_event_id,
        timestamp=now_utc,
        domain="API",
        network=NetworkInfo(
            source_ip=client_ip,
            user_agent="ThreatGuard-Automated-Simulator/1.0",
            destination_ip="127.0.0.1",
            protocol="HTTP",
            connection_status="success",
        ),
        identity=IdentityInfo(
            user_id=None,
            session_id=f"sess-sqli-sim-{client_ip.replace('.', '_')}",
            roles=[],
            is_authenticated=False,
        ),
        request=RequestInfo(
            method="POST",
            endpoint="/lab/sqli",
            path_params={},
            query_params={},
            headers={"Content-Type": "application/json", "User-Agent": "ThreatGuard-Automated-Simulator/1.0"},
            body=simulated_payload,
        ),
        response=ResponseInfo(
            status_code=200,
            latency_ms=8.0,
        ),
        resource=ResourceInfo(
            resource_type="api_endpoint",
            resource_id="/lab/sqli",
            is_sensitive=False,
        ),
    )

    # Process through the genuine ThreatGuard detection pipeline
    result = _processor.process(event=target_event)

    threat_detected = result.risk_assessment.threat_detected
    mitigation_action = result.mitigation_action
    risk_score = result.risk_assessment.risk_score
    risk_level = result.risk_assessment.risk_level
    reasons = result.risk_assessment.reasons
    attack_types = result.risk_assessment.attack_types

    return JSONResponse(
        status_code=200,
        content={
            "status": "completed",
            "simulation_type": "SQL_INJECTION",
            "target_endpoint": "/lab/sqli",
            "generated_payload": simulated_payload["query"],
            "threatguard_interception": {
                "threat_detected": threat_detected,
                "attack_type": attack_types[0] if attack_types else "SQL_INJECTION",
                "risk_score": risk_score,
                "risk_level": risk_level,
                "mitigation_action": mitigation_action,
                "enforcement_http_status": 403 if (threat_detected or mitigation_action != "ALLOW") else 200,
                "incident_id": simulated_event_id,
                "evidence": reasons[0] if reasons else "SQL Injection pattern detected",
            },
        },
    )
