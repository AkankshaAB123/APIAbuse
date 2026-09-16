import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Activity, ShieldAlert, Database, Server } from "lucide-react";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
import { getStatistics, getThreats } from "../services/api";
import { formatAttackType } from "../data/attackTypes";

function ApiInventory() {
  const [statistics, setStatistics] = useState(null);
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadInventory = async () => {
    try {
      setLoading(true);
      setError("");
      const [stats, threatData] = await Promise.all([getStatistics(), getThreats()]);
      setStatistics(stats);
      setThreats(Array.isArray(threatData) ? threatData : []);
    } catch (err) {
      setError(err.message || "Unable to load API inventory.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadInventory();
  }, []);

  const endpoints = useMemo(() => {
    const map = new Map();

    threats.forEach((threat) => {
      const endpoint = threat.endpoint || "Unknown endpoint";
      const existing = map.get(endpoint) || {
        endpoint,
        method: threat.method || "GET",
        threats: 0,
        highestRisk: 0,
        recentThreats: [],
        domain: threat.domain || "API"
      };

      existing.threats++;
      const riskScore = threat.riskScore || 0;
      if (riskScore > existing.highestRisk) {
        existing.highestRisk = riskScore;
      }

      if (existing.recentThreats.length < 3) {
        existing.recentThreats.push(threat);
      }

      map.set(endpoint, existing);
    });

    return Array.from(map.values()).sort((a, b) => b.highestRisk - a.highestRisk);
  }, [threats]);

  const getMethodColor = (method) => {
    switch(method) {
      case 'GET': return '#3b82f6';
      case 'POST': return '#22c55e';
      case 'PUT': return '#eab308';
      case 'DELETE': return '#ef4444';
      default: return '#94a3b8';
    }
  };

  const getRiskLabel = (score) => {
    if (score >= 90) return { label: 'CRITICAL', color: '#ef4444', class: 'severity-critical' };
    if (score >= 70) return { label: 'HIGH', color: '#f97316', class: 'severity-high' };
    if (score >= 40) return { label: 'MEDIUM', color: '#f59e0b', class: 'severity-medium' };
    return { label: 'LOW', color: '#10b981', class: 'severity-low' };
  };

  return (
    <main className="page-content">
      <div className="page-header">
        <div>
          <div className="page-kicker">ENTERPRISE</div>
          <h1>API Inventory</h1>
          <p>Endpoint security posture derived from real detected threat records.</p>
        </div>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <span>Requests Monitored</span>
          <strong>{statistics?.totalEvents ?? 0}</strong>
          <Activity size={24} style={{position: "absolute", top: 24, right: 24, color: "#3b82f6", opacity: 0.5}} />
        </div>
        <div className="stat-card">
          <span>Threats Detected</span>
          <strong>{statistics?.totalThreats ?? 0}</strong>
          <ShieldAlert size={24} style={{position: "absolute", top: 24, right: 24, color: "#ef4444", opacity: 0.5}} />
        </div>
        <div className="stat-card">
          <span>Active Endpoints</span>
          <strong>{endpoints.length}</strong>
          <Server size={24} style={{position: "absolute", top: 24, right: 24, color: "#10b981", opacity: 0.5}} />
        </div>
      </div>

      {loading && <LoadingState />}
      {!loading && error && <ErrorState message={error} onRetry={loadInventory} />}
      {!loading && !error && endpoints.length === 0 && (
        <EmptyState
          title="No endpoint threat inventory yet."
          message="Endpoint posture will populate from real detected threats."
        />
      )}

      {!loading && !error && endpoints.length > 0 && (
        <div className="table-container">
          <table className="threat-table">
            <thead>
              <tr>
                <th>Method</th>
                <th>Endpoint Path</th>
                <th>Domain</th>
                <th>Threat Count</th>
                <th>Max Risk</th>
                <th>Recent Vectors</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map((ep, idx) => {
                const riskInfo = getRiskLabel(ep.highestRisk);
                return (
                  <tr key={idx}>
                    <td>
                      <span style={{
                        color: getMethodColor(ep.method),
                        fontWeight: 700,
                        fontSize: "12px",
                        background: "rgba(255,255,255,0.05)",
                        padding: "4px 8px",
                        borderRadius: "4px"
                      }}>
                        {ep.method}
                      </span>
                    </td>
                    <td style={{ fontFamily: "monospace", color: "#f1f5f9", fontSize: "14px" }}>{ep.endpoint}</td>
                    <td><span className="alert-domain">{ep.domain}</span></td>
                    <td>{ep.threats}</td>
                    <td>
                      <span className={"status-badge-inline "}>{riskInfo.label} ({ep.highestRisk})</span>
                    </td>
                    <td>
                      <div className="reason-list" style={{justifyContent: "flex-start"}}>
                        {ep.recentThreats.map((t, i) => (
                          <span key={i} className="reason-badge">{formatAttackType(t.attackType)}</span>
                        ))}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </main>
  );
}

export default ApiInventory;
