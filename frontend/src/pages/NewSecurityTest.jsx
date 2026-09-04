import { useState } from "react";
import { Link } from "react-router-dom";
import { Play, ShieldAlert } from "lucide-react";
import RiskBadge from "../components/RiskBadge";
import { ErrorState } from "../components/States";
import { ATTACK_SCENARIOS } from "../data/attackTypes";
import { processEvent } from "../services/api";

function createEventId() {
  return `CUSTOM-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function parseJson(value, fallback) {
  if (!value.trim()) {
    return fallback;
  }

  return JSON.parse(value);
}

function buildEvent(form, scenario, parsedBody, parsedHeaders) {
  const userId = form.userId || "custom-test-user";

  return {
    schema_version: "1.0",
    event_id: createEventId(),
    timestamp: new Date().toISOString(),
    network: {
      source_ip: form.sourceIp || "192.168.1.100",
      user_agent: "ThreatGuard-Custom-Test",
    },
    identity: {
      user_id: userId,
      session_id: `session-${userId}`,
      roles: form.attackId === "privilege" ? ["user"] : ["user"],
      is_authenticated: scenario.is_authenticated ?? true,
    },
    request: {
      method: form.method,
      endpoint: form.endpoint,
      path_params: {
        object_id: scenario.resource_id || "custom-resource",
      },
      query_params: scenario.query_params || {},
      headers: {
        "X-Security-Test": "true",
        ...parsedHeaders,
      },
      body: form.method === "GET" ? null : parsedBody,
    },
    response: {
      status_code: Number(scenario.status_code || 200),
      latency_ms: 120,
    },
    resource: {
      resource_type: scenario.resource_type || "api_resource",
      resource_id: scenario.resource_id || "custom-resource",
      owner_id: form.attackId === "bola" ? "protected_owner" : userId,
      is_sensitive: Boolean(scenario.is_sensitive),
    },
  };
}

function NewSecurityTest() {
  const [attackId, setAttackId] = useState("sql-injection");
  const scenario = ATTACK_SCENARIOS.find((item) => item.id === attackId) || ATTACK_SCENARIOS[0];
  const [form, setForm] = useState({
    attackId,
    endpoint: scenario.endpoint,
    method: scenario.method,
    sourceIp: "192.168.1.100",
    userId: "custom-test-user",
  });
  const [payload, setPayload] = useState(JSON.stringify(scenario.body || scenario.query_params || {}, null, 2));
  const [headers, setHeaders] = useState("{}");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const selectAttack = (nextAttackId) => {
    const nextScenario =
      ATTACK_SCENARIOS.find((item) => item.id === nextAttackId) ||
      ATTACK_SCENARIOS[0];

    setAttackId(nextAttackId);
    setForm((current) => ({
      ...current,
      attackId: nextAttackId,
      endpoint: nextScenario.endpoint,
      method: nextScenario.method,
    }));
    setPayload(JSON.stringify(nextScenario.body || nextScenario.query_params || {}, null, 2));
  };

  const runTest = async (event) => {
    event.preventDefault();
    setRunning(true);
    setError("");
    setResult(null);

    try {
      const parsedPayload = parseJson(payload, {});
      const parsedHeaders = parseJson(headers, {});
      const backendEvent = buildEvent(
        {
          ...form,
          attackId,
        },
        scenario,
        parsedPayload,
        parsedHeaders
      );

      const response = await processEvent(backendEvent);
      localStorage.setItem("latestThreat", JSON.stringify(response));
      setResult(response);
    } catch (err) {
      setError(err.message || "Unable to run the security test.");
    } finally {
      setRunning(false);
    }
  };

  return (
    <main className="page-content">
      <div className="page-header">
        <div>
          <div className="page-kicker">SECURITY TESTING</div>
          <h1>Create Security Test</h1>
          <p>Send a controlled event through the live detection, risk, MongoDB, RAG, and Gemini pipeline.</p>
        </div>
      </div>

      <div className="test-console-grid">
        <form className="security-test-form" onSubmit={runTest}>
          <label>
            Attack Type
            <select value={attackId} onChange={(event) => selectAttack(event.target.value)}>
              {ATTACK_SCENARIOS.map((attack) => (
                <option key={attack.id} value={attack.id}>
                  {attack.name}
                </option>
              ))}
            </select>
          </label>

          <label>
            Endpoint
            <input
              value={form.endpoint}
              onChange={(event) => setForm({ ...form, endpoint: event.target.value })}
            />
          </label>

          <label>
            HTTP Method
            <select
              value={form.method}
              onChange={(event) => setForm({ ...form, method: event.target.value })}
            >
              <option>GET</option>
              <option>POST</option>
              <option>PUT</option>
              <option>PATCH</option>
              <option>DELETE</option>
            </select>
          </label>

          <label>
            Source IP
            <input
              value={form.sourceIp}
              onChange={(event) => setForm({ ...form, sourceIp: event.target.value })}
            />
          </label>

          <label>
            User ID
            <input
              value={form.userId}
              onChange={(event) => setForm({ ...form, userId: event.target.value })}
            />
          </label>

          <label>
            Payload / Request Data
            <textarea value={payload} onChange={(event) => setPayload(event.target.value)} rows={9} />
          </label>

          <label>
            Optional Headers
            <textarea value={headers} onChange={(event) => setHeaders(event.target.value)} rows={4} />
          </label>

          <button className="primary-action" type="submit" disabled={running}>
            <Play size={17} />
            {running ? "RUNNING TEST..." : "RUN SECURITY TEST"}
          </button>
        </form>

        <section className="test-result-panel">
          <div className="section-header">
            <h2>Detection Result</h2>
            <ShieldAlert size={20} />
          </div>

          <p className="placeholder-text">{scenario.description}</p>

          {error && <ErrorState message={error} />}

          {result && (
            <div className="result-stack">
              <div className="result-row">
                <span>Threat ID</span>
                <strong>{result.event_id}</strong>
              </div>
              <div className="result-row">
                <span>Detected</span>
                <strong>{result.risk_assessment?.threat_detected ? "YES" : "NO"}</strong>
              </div>
              <div className="result-row">
                <span>Risk</span>
                <RiskBadge
                  score={result.risk_assessment?.risk_score ?? 0}
                  severity={result.risk_assessment?.risk_level || "LOW"}
                />
              </div>
              <div className="result-row">
                <span>Action</span>
                <strong>{result.mitigation_action || "ALLOW"}</strong>
              </div>
              <div className="result-row">
                <span>Detectors Executed</span>
                <strong>{result.detector_results?.length || 0}</strong>
              </div>

              <Link className="view-threat-button" to={`/threat/${result.event_id}`}>
                VIEW THREAT
              </Link>
            </div>
          )}
        </section>
      </div>
    </main>
  );
}

export default NewSecurityTest;
