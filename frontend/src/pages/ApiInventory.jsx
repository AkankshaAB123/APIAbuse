import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Activity, ShieldAlert } from "lucide-react";
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
        threats: 0,
        highestRisk: 0,
        attackTypes: new Set(),
        latestThreat: threat.id,
      };

      existing.threats += 1;
      existing.highestRisk = Math.max(existing.highestRisk, Number(threat.riskScore || 0));
      (threat.attackTypes || [threat.attackType]).forEach((type) => {
        if (type) {
          existing.attackTypes.add(type);
        }
      });
      existing.latestThreat = threat.id;
      map.set(endpoint, existing);
    });

    return Array.from(map.values())
      .map((item) => ({
        ...item,
        attackTypes: Array.from(item.attackTypes),
        status: item.highestRisk >= 80 ? "ATTENTION" : item.highestRisk >= 50 ? "WATCH" : "STABLE",
      }))
      .sort((a, b) => b.highestRisk - a.highestRisk);
  }, [threats]);

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
        <div className="enterprise-stat-card">
          <div className="enterprise-stat-icon enterprise-blue"><Activity size={23} /></div>
          <div><span>Requests Monitored</span><strong>{statistics?.totalEvents ?? 0}</strong><small>Backend event records</small></div>
        </div>
        <div className="enterprise-stat-card">
          <div className="enterprise-stat-icon enterprise-red"><ShieldAlert size={23} /></div>
          <div><span>Threats Detected</span><strong>{statistics?.totalThreats ?? 0}</strong><small>Detected API abuse</small></div>
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
        <div className="inventory-table">
          <div className="inventory-row inventory-head">
            <span>Endpoint</span>
            <span>Threats</span>
            <span>Highest Risk</span>
            <span>Detected Risks</span>
            <span>Status</span>
          </div>
          {endpoints.map((endpoint) => (
            <Link
              className="inventory-row"
              key={endpoint.endpoint}
              to={`/threat/${endpoint.latestThreat}`}
            >
              <strong>{endpoint.endpoint}</strong>
              <span>{endpoint.threats}</span>
              <span>{endpoint.highestRisk}</span>
              <span>{endpoint.attackTypes.map(formatAttackType).join(", ") || "Unknown"}</span>
              <span className={`posture-status ${endpoint.status.toLowerCase()}`}>
                {endpoint.status}
              </span>
            </Link>
          ))}
        </div>
      )}
    </main>
  );
}

export default ApiInventory;
