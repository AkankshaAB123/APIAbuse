import { useState } from "react";

const attackScenarios = [
  {
    id: "bola",
    name: "BOLA / IDOR",
    description:
      "Simulates unauthorized access to another user's resource by manipulating an object ID.",
    method: "GET",
    endpoint: "/api/orders/42",
    payload: {
      user_id: "user_17",
      target_user_id: "user_42",
      object_id: "42",
    },
  },
  {
    id: "privilege",
    name: "Privilege Escalation",
    description:
      "Simulates a user attempting to access a function or resource requiring higher privileges.",
    method: "POST",
    endpoint: "/api/admin/users",
    payload: {
      user_id: "user_17",
      role: "user",
      requested_role: "admin",
    },
  },
  {
    id: "credential",
    name: "Credential Attack",
    description:
      "Simulates repeated failed authentication attempts against an API account.",
    method: "POST",
    endpoint: "/api/login",
    payload: {
      username: "demo_user",
      failed_attempts: 12,
      source_ip: "192.168.1.10",
    },
  },
  {
    id: "account-takeover",
    name: "Account Takeover",
    description:
      "Simulates suspicious use of valid account credentials from an unusual source.",
    method: "POST",
    endpoint: "/api/account",
    payload: {
      user_id: "user_17",
      token_id: "token_7842",
      source_ip: "192.168.1.10",
      unusual_location: true,
    },
  },
  {
    id: "sql-injection",
    name: "SQL Injection",
    description:
      "Simulates a suspicious API request containing an SQL injection pattern.",
    method: "GET",
    endpoint: "/api/users?id=1",
    payload: {
      parameter: "id",
      suspicious_pattern: "' OR '1'='1",
    },
  },
  {
    id: "ssrf",
    name: "SSRF",
    description:
      "Simulates an API request attempting to make the server access a restricted resource.",
    method: "POST",
    endpoint: "/api/fetch",
    payload: {
      url: "http://127.0.0.1:8080/internal",
      source_ip: "192.168.1.10",
    },
  },
  {
    id: "resource",
    name: "Resource Exhaustion",
    description:
      "Simulates high-volume requests targeting a resource-intensive API endpoint.",
    method: "GET",
    endpoint: "/api/search",
    payload: {
      request_count: 500,
      time_window: "10 seconds",
      source_ip: "192.168.1.10",
    },
  },
  {
    id: "misconfiguration",
    name: "Security Misconfiguration",
    description:
      "Simulates access to an exposed or improperly protected API endpoint.",
    method: "GET",
    endpoint: "/api/debug",
    payload: {
      authentication: "missing",
      exposed_endpoint: true,
    },
  },
  {
    id: "business-flow",
    name: "Business Flow Abuse",
    description:
      "Simulates abnormal use of a legitimate business workflow.",
    method: "POST",
    endpoint: "/api/checkout",
    payload: {
      user_id: "user_17",
      quantity: 1000,
      repeated_requests: true,
    },
  },
  {
    id: "recon",
    name: "API Reconnaissance",
    description:
      "Simulates repeated requests used to discover available API endpoints.",
    method: "GET",
    endpoint: "/api/",
    payload: {
      endpoints_requested: 25,
      time_window: "30 seconds",
      source_ip: "192.168.1.10",
    },
  },
];

function AttackSimulation() {
  const [selectedAttack, setSelectedAttack] = useState(
    attackScenarios[0]
  );

  const [logs, setLogs] = useState([
    "> Attack Simulation Console initialized.",
    "> Controlled local demonstration mode.",
    "> Select an attack scenario to begin.",
  ]);

  const [running, setRunning] = useState(false);

  const runSimulation = () => {
    if (running) return;

    setRunning(true);

    setLogs([
      "> Simulation started.",
      `> Attack: ${selectedAttack.name}`,
      `> Method: ${selectedAttack.method}`,
      `> Endpoint: ${selectedAttack.endpoint}`,
      "> Sending predefined request...",
    ]);

    setTimeout(() => {
      setLogs((previousLogs) => [
        ...previousLogs,
        "> Request sent successfully.",
        "> HTTP Status: 200",
        "> Detection system response received.",
        `> Detection: ${selectedAttack.name}`,
        "> Risk Score: PENDING BACKEND",
        "> Severity: PENDING BACKEND",
        "> Alert generated: PENDING BACKEND",
        "> Simulation completed.",
      ]);

      setRunning(false);
    }, 1000);
  };

  return (
    <div className="attack-simulation-page">
      <div className="attack-simulation-header">
        <div>
          <div className="page-kicker">APIABUSE SECURITY LAB</div>

          <h1>Attack Simulation Console</h1>

          <p>
            Controlled API security testing environment for local
            demonstration.
          </p>
        </div>

        <div className="demo-status">
          <span className="status-dot"></span>
          LOCAL DEMO MODE
        </div>
      </div>

      <div className="simulation-layout">
        {/* ATTACK SCENARIOS */}

        <div className="attack-list-panel">
          <div className="panel-title">
            <span>ATTACK SCENARIOS</span>
            <span className="attack-count">
              {attackScenarios.length}
            </span>
          </div>

          <div className="attack-list">
            {attackScenarios.map((attack) => (
              <button
                key={attack.id}
                className={`attack-item ${
                  selectedAttack.id === attack.id
                    ? "active"
                    : ""
                }`}
                onClick={() => {
                  setSelectedAttack(attack);

                  setLogs([
                    "> Attack selected.",
                    `> Scenario: ${attack.name}`,
                    "> Ready for simulation.",
                  ]);
                }}
              >
                <span className="attack-indicator">›</span>

                <span>{attack.name}</span>
              </button>
            ))}
          </div>
        </div>

        {/* MAIN SIMULATION AREA */}

        <div className="simulation-main">
          <div className="selected-attack-card">
            <div className="selected-attack-top">
              <div>
                <div className="section-label">
                  SELECTED ATTACK
                </div>

                <h2>{selectedAttack.name}</h2>
              </div>

              <div className="attack-tag">
                SIMULATION
              </div>
            </div>

            <p className="attack-description">
              {selectedAttack.description}
            </p>

            <div className="request-section">
              <div className="section-label">
                PREDEFINED REQUEST
              </div>

              <div className="request-box">
                <div className="request-line">
                  <span className="method">
                    {selectedAttack.method}
                  </span>

                  <span>
                    {selectedAttack.endpoint}
                  </span>
                </div>

                <div className="request-user">
                  Controlled demonstration payload
                </div>

                <pre>
                  {JSON.stringify(
                    selectedAttack.payload,
                    null,
                    2
                  )}
                </pre>
              </div>
            </div>

            <button
              className="execute-button"
              onClick={runSimulation}
              disabled={running}
            >
              {running
                ? "RUNNING SIMULATION..."
                : "▶  EXECUTE SIMULATION"}
            </button>
          </div>

          {/* TERMINAL */}

          <div className="console-panel">
            <div className="console-header">
              <div className="console-title">
                <span className="terminal-icon">●</span>
                SIMULATION OUTPUT
              </div>

              <div className="console-status">
                READY
              </div>
            </div>

            <div className="console-body">
              {logs.map((log, index) => (
                <div
                  key={`${log}-${index}`}
                  className={
                    log.includes("Detection:")
                      ? "log-detection"
                      : log.includes("Risk Score:")
                      ? "log-risk"
                      : "log-line"
                  }
                >
                  {log}
                </div>
              ))}

              <span className="cursor">_</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default AttackSimulation;