import { useEffect, useState } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Activity,
  Cpu,
  RefreshCw,
  Lock,
  Server,
  Zap,
  Bot,
  ExternalLink,
  Info
} from "lucide-react";
import { getThreats } from "../services/api";
import { formatAttackType } from "../data/attackTypes";
import ThreatDetails from "./ThreatDetails";

export default function DeviceDashboard({ user }) {
  const deviceIp = user?.device_ip || "10.165.192.186";
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedThreatId, setSelectedThreatId] = useState(null);
  const [showExtensionModal, setShowExtensionModal] = useState(false);

  const fetchDeviceThreats = async () => {
    setLoading(true);
    setError("");
    try {
      const data = await getThreats(); // Device scope derived strictly from authenticated JWT
      setThreats(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err?.message || "Failed to load device security telemetry");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDeviceThreats();
    const interval = setInterval(fetchDeviceThreats, 10000);
    return () => clearInterval(interval);
  }, [deviceIp]);

  const activeIncidents = threats.filter((t) => t.threatDetected !== false);
  const highestRisk = activeIncidents.reduce(
    (max, t) => (t.riskScore > max ? t.riskScore : max),
    0
  );

  let protectionStatus = "SECURE";
  let statusColor = "var(--color-success, #10b981)";
  if (activeIncidents.length > 0) {
    const hasRateLimit = activeIncidents.some((t) => t.action === "RATE_LIMIT");
    const hasBlock = activeIncidents.some((t) => t.action === "BLOCK");
    if (hasBlock) {
      protectionStatus = "BLOCKED_HOST_DEFENSE";
      statusColor = "var(--color-danger, #ef4444)";
    } else if (hasRateLimit) {
      protectionStatus = "RATE_LIMITED_PROTECTED";
      statusColor = "var(--color-warning, #f59e0b)";
    } else {
      protectionStatus = "ELEVATED_THREAT_ACTIVE";
      statusColor = "#8b5cf6";
    }
  }

  if (selectedThreatId) {
    return (
      <div className="device-threat-details-container">
        <button
          className="btn-back-overview"
          onClick={() => setSelectedThreatId(null)}
          style={{
            marginBottom: "1rem",
            background: "rgba(255, 255, 255, 0.08)",
            border: "1px solid rgba(255, 255, 255, 0.15)",
            color: "#fff",
            padding: "0.5rem 1rem",
            borderRadius: "6px",
            cursor: "pointer",
            display: "inline-flex",
            alignItems: "center",
            gap: "0.5rem"
          }}
        >
          &larr; Back to Device Protection Overview
        </button>
        <ThreatDetails threatId={selectedThreatId} />
      </div>
    );
  }

  return (
    <div className="device-dashboard" style={{ padding: "1.5rem", maxWidth: "1200px", margin: "0 auto" }}>
      {/* Header Banner */}
      <div
        className="device-header"
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "1.5rem",
          paddingBottom: "1rem",
          borderBottom: "1px solid rgba(255, 255, 255, 0.1)"
        }}
      >
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
            <Server size={28} color="#38bdf8" />
            <h1 style={{ margin: 0, fontSize: "1.75rem", fontWeight: 700 }}>
              Device Security Console
            </h1>
          </div>
          <p style={{ margin: "0.25rem 0 0", color: "#94a3b8", fontSize: "0.9rem" }}>
            Real-time endpoint active defense &amp; incident scope for host:{" "}
            <code style={{ background: "rgba(56, 189, 248, 0.15)", color: "#38bdf8", padding: "0.1rem 0.4rem", borderRadius: "4px" }}>
              {deviceIp}
            </code>
          </p>
        </div>

        <div style={{ display: "flex", gap: "1rem" }}>
          <button
            onClick={() => setShowExtensionModal(true)}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.5rem",
              background: "#2563eb",
              border: "1px solid #1d4ed8",
              color: "white",
              padding: "0.5rem 1rem",
              borderRadius: "6px",
              cursor: "pointer",
              fontWeight: 500
            }}
          >
            <ShieldCheck size={16} />
            Extension for XSS Attacks
          </button>
          <button
            onClick={fetchDeviceThreats}
            disabled={loading}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.5rem",
              background: "rgba(56, 189, 248, 0.1)",
              border: "1px solid rgba(56, 189, 248, 0.3)",
              color: "#38bdf8",
              padding: "0.5rem 1rem",
              borderRadius: "6px",
              cursor: "pointer",
              fontWeight: 500
            }}
          >
            <RefreshCw size={16} className={loading ? "spin" : ""} />
            Refresh Telemetry
          </button>
        </div>
      </div>

      {error && (
        <div
          style={{
            background: "rgba(239, 68, 68, 0.15)",
            border: "1px solid rgba(239, 68, 68, 0.4)",
            color: "#fca5a5",
            padding: "1rem",
            borderRadius: "8px",
            marginBottom: "1.5rem"
          }}
        >
          {error}
        </div>
      )}

      {/* Device Status Metric Cards */}
      <div
        className="device-metrics-grid"
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
          gap: "1rem",
          marginBottom: "2rem"
        }}
      >
        <div
          style={{
            background: "rgba(15, 23, 42, 0.7)",
            border: "1px solid rgba(255, 255, 255, 0.08)",
            borderRadius: "10px",
            padding: "1.25rem"
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", color: "#94a3b8", fontSize: "0.85rem" }}>
            <span>Active Protection State</span>
            <ShieldCheck size={18} color={statusColor} />
          </div>
          <div style={{ fontSize: "1.35rem", fontWeight: 700, color: statusColor, marginTop: "0.5rem" }}>
            {protectionStatus}
          </div>
          <div style={{ fontSize: "0.8rem", color: "#64748b", marginTop: "0.25rem" }}>
            Gateway real-enforcement active
          </div>
        </div>

        <div
          style={{
            background: "rgba(15, 23, 42, 0.7)",
            border: "1px solid rgba(255, 255, 255, 0.08)",
            borderRadius: "10px",
            padding: "1.25rem"
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", color: "#94a3b8", fontSize: "0.85rem" }}>
            <span>Incidents Targeting Device</span>
            <ShieldAlert size={18} color="#f87171" />
          </div>
          <div style={{ fontSize: "1.5rem", fontWeight: 700, color: "#fff", marginTop: "0.5rem" }}>
            {activeIncidents.length}
          </div>
          <div style={{ fontSize: "0.8rem", color: "#64748b", marginTop: "0.25rem" }}>
            Strictly scoped to {deviceIp}
          </div>
        </div>

        <div
          style={{
            background: "rgba(15, 23, 42, 0.7)",
            border: "1px solid rgba(255, 255, 255, 0.08)",
            borderRadius: "10px",
            padding: "1.25rem"
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", color: "#94a3b8", fontSize: "0.85rem" }}>
            <span>Max Incident Risk Score</span>
            <Activity size={18} color="#fbbf24" />
          </div>
          <div style={{ fontSize: "1.5rem", fontWeight: 700, color: highestRisk > 70 ? "#f87171" : highestRisk > 40 ? "#fbbf24" : "#34d399", marginTop: "0.5rem" }}>
            {highestRisk.toFixed(1)}
          </div>
          <div style={{ fontSize: "0.8rem", color: "#64748b", marginTop: "0.25rem" }}>
            Intelligent IDS Assessment
          </div>
        </div>

        <div
          style={{
            background: "rgba(15, 23, 42, 0.7)",
            border: "1px solid rgba(255, 255, 255, 0.08)",
            borderRadius: "10px",
            padding: "1.25rem"
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", color: "#94a3b8", fontSize: "0.85rem" }}>
            <span>Assigned Protected IP</span>
            <Lock size={18} color="#38bdf8" />
          </div>
          <div style={{ fontSize: "1.25rem", fontWeight: 600, color: "#e2e8f0", marginTop: "0.5rem" }}>
            {deviceIp}
          </div>
          <div style={{ fontSize: "0.8rem", color: "#64748b", marginTop: "0.25rem" }}>
            Identity isolation enabled
          </div>
        </div>
      </div>

      {/* Incidents Table for This Device */}
      <div
        style={{
          background: "rgba(15, 23, 42, 0.7)",
          border: "1px solid rgba(255, 255, 255, 0.08)",
          borderRadius: "10px",
          padding: "1.5rem"
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
          <div>
            <h2 style={{ margin: 0, fontSize: "1.25rem", fontWeight: 600 }}>
              Security Incidents on this Device
            </h2>
            <p style={{ margin: "0.25rem 0 0", color: "#94a3b8", fontSize: "0.85rem" }}>
              Inbound attacks mitigated by the enforcement gateway before execution
            </p>
          </div>
          <span style={{ fontSize: "0.85rem", color: "#64748b" }}>
            Showing {threats.length} recorded events
          </span>
        </div>

        {threats.length === 0 ? (
          <div
            style={{
              padding: "3rem 1rem",
              textAlign: "center",
              color: "#64748b"
            }}
          >
            <ShieldCheck size={48} color="#10b981" style={{ margin: "0 auto 1rem", opacity: 0.7 }} />
            <div style={{ fontSize: "1.1rem", fontWeight: 500, color: "#94a3b8" }}>
              No threat incidents recorded for {deviceIp}
            </div>
            <p style={{ maxWidth: "450px", margin: "0.5rem auto 0", fontSize: "0.85rem" }}>
              The endpoint is actively guarded. Inbound attacks intercepted by the ThreatGuard Gateway will appear here in real-time.
            </p>
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.1)", textAlign: "left", color: "#94a3b8" }}>
                  <th style={{ padding: "0.75rem 0.5rem" }}>Timestamp</th>
                  <th style={{ padding: "0.75rem 0.5rem" }}>Attacker IP</th>
                  <th style={{ padding: "0.75rem 0.5rem" }}>Target Endpoint</th>
                  <th style={{ padding: "0.75rem 0.5rem" }}>Attack Type</th>
                  <th style={{ padding: "0.75rem 0.5rem" }}>Risk</th>
                  <th style={{ padding: "0.75rem 0.5rem" }}>Mitigation</th>
                  <th style={{ padding: "0.75rem 0.5rem" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {threats.map((threat) => {
                  const riskColor =
                    threat.severity === "CRITICAL"
                      ? "#ef4444"
                      : threat.severity === "HIGH"
                      ? "#f97316"
                      : threat.severity === "MEDIUM"
                      ? "#eab308"
                      : "#22c55e";

                  const actionBg =
                    threat.action === "RATE_LIMIT"
                      ? "rgba(245, 158, 11, 0.2)"
                      : threat.action === "BLOCK"
                      ? "rgba(239, 68, 68, 0.2)"
                      : "rgba(16, 185, 129, 0.2)";

                  const actionColor =
                    threat.action === "RATE_LIMIT"
                      ? "#f59e0b"
                      : threat.action === "BLOCK"
                      ? "#ef4444"
                      : "#10b981";

                  return (
                    <tr
                      key={threat.id}
                      style={{
                        borderBottom: "1px solid rgba(255, 255, 255, 0.05)",
                        transition: "background 0.2s"
                      }}
                    >
                      <td style={{ padding: "0.75rem 0.5rem", color: "#94a3b8", whiteSpace: "nowrap" }}>
                        {new Date(threat.timestamp).toLocaleTimeString()}
                      </td>
                      <td style={{ padding: "0.75rem 0.5rem" }}>
                        <code style={{ background: "rgba(255, 255, 255, 0.05)", padding: "0.2rem 0.4rem", borderRadius: "4px" }}>
                          {threat.sourceIp || "Unknown"}
                        </code>
                      </td>
                      <td style={{ padding: "0.75rem 0.5rem", color: "#cbd5e1" }}>
                        <code style={{ color: "#38bdf8" }}>{threat.endpoint || "/"}</code>
                      </td>
                      <td style={{ padding: "0.75rem 0.5rem", fontWeight: 500, color: "#f1f5f9" }}>
                        {formatAttackType(threat.attackType)}
                      </td>
                      <td style={{ padding: "0.75rem 0.5rem" }}>
                        <span
                          style={{
                            color: riskColor,
                            fontWeight: 600,
                            display: "inline-flex",
                            alignItems: "center",
                            gap: "0.3rem"
                          }}
                        >
                          {threat.riskScore?.toFixed(1) || "0.0"} ({threat.severity || "LOW"})
                        </span>
                      </td>
                      <td style={{ padding: "0.75rem 0.5rem" }}>
                        <span
                          style={{
                            background: actionBg,
                            color: actionColor,
                            padding: "0.2rem 0.6rem",
                            borderRadius: "999px",
                            fontSize: "0.75rem",
                            fontWeight: 600,
                            letterSpacing: "0.03em"
                          }}
                        >
                          {threat.action || "ALLOW"}
                        </span>
                      </td>
                      <td style={{ padding: "0.75rem 0.5rem" }}>
                        <button
                          onClick={() => setSelectedThreatId(threat.id)}
                          style={{
                            background: "rgba(255, 255, 255, 0.06)",
                            border: "1px solid rgba(255, 255, 255, 0.15)",
                            color: "#94a3b8",
                            padding: "0.3rem 0.6rem",
                            borderRadius: "4px",
                            cursor: "pointer",
                            fontSize: "0.8rem",
                            display: "inline-flex",
                            alignItems: "center",
                            gap: "0.3rem"
                          }}
                        >
                          <Info size={13} />
                          Details
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
      
      {/* Extension Installation Modal */}
      {showExtensionModal && (
        <div style={{
          position: "fixed",
          top: 0, left: 0, right: 0, bottom: 0,
          background: "rgba(0,0,0,0.7)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          zIndex: 9999
        }}>
          <div style={{
            background: "#1e293b",
            border: "1px solid rgba(255,255,255,0.1)",
            borderRadius: "10px",
            padding: "2rem",
            maxWidth: "500px",
            width: "90%",
            boxShadow: "0 10px 25px rgba(0,0,0,0.5)",
            color: "white"
          }}>
            <h2 style={{ margin: "0 0 1rem 0", display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <ShieldCheck size={24} color="#38bdf8" />
              Install ThreatGuard Extension
            </h2>
            
            <p style={{ color: "#94a3b8", marginBottom: "1rem", lineHeight: "1.5" }}>
              <strong>What is this?</strong> The ThreatGuard Extension acts as a personal bodyguard for your browser. It silently monitors your web traffic and instantly blocks malicious links (like Cross-Site Scripting attacks) before they can steal your data.
            </p>
            
            <p style={{ color: "#94a3b8", marginBottom: "1.5rem", lineHeight: "1.5" }}>
              <em>Note: Modern browsers prevent websites from installing extensions automatically for security reasons. To protect your browser, you'll need to load the extension manually:</em>
            </p>
            
            <ol style={{ color: "#cbd5e1", lineHeight: "1.6", marginBottom: "2rem", paddingLeft: "1.5rem" }}>
              <li>Click the button below to download the <strong>threatguard_extension.zip</strong> file.</li>
              <li>Extract/unzip the downloaded file to a folder on your computer.</li>
              <li>Open your browser and navigate to <code>chrome://extensions</code> (or <code>edge://extensions</code>).</li>
              <li>Turn on <strong>Developer Mode</strong> in the top-right corner.</li>
              <li>Click <strong>Load unpacked</strong> and select the folder you extracted in step 2.</li>
            </ol>
            
            <div style={{ display: "flex", gap: "1rem", justifyContent: "flex-end" }}>
              <button 
                onClick={() => setShowExtensionModal(false)}
                style={{
                  background: "transparent",
                  border: "1px solid rgba(255,255,255,0.2)",
                  color: "#cbd5e1",
                  padding: "0.5rem 1rem",
                  borderRadius: "6px",
                  cursor: "pointer"
                }}
              >
                Close
              </button>
              <a
                href="http://localhost:8000/static/threatguard_extension.zip"
                download
                onClick={() => setTimeout(() => setShowExtensionModal(false), 1000)}
                style={{
                  background: "#2563eb",
                  border: "none",
                  color: "white",
                  padding: "0.5rem 1rem",
                  borderRadius: "6px",
                  cursor: "pointer",
                  textDecoration: "none",
                  fontWeight: 500,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "0.5rem"
                }}
              >
                <ShieldCheck size={16} />
                Download Zip File
              </a>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
