import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, Bell } from "lucide-react";
import RiskBadge from "../components/RiskBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
import { getThreats } from "../services/api";
import { formatAttackType } from "../data/attackTypes";

function formatTime(timestamp) {
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime())
    ? "Unknown time"
    : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function AlertsPage() {
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadAlerts = async () => {
    try {
      setLoading(true);
      setError("");
      const data = await getThreats();
      setThreats(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err.message || "Unable to load alerts.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, []);

  const alerts = threats.filter((threat) =>
    ["CRITICAL", "HIGH"].includes(threat.severity)
  );

  return (
    <main className="page-content">
      <div className="page-header">
        <div>
          <div className="page-kicker">THREAT MANAGEMENT</div>
          <h1>Security Alerts</h1>
          <p>High-priority API abuse events from MongoDB threat history.</p>
        </div>
      </div>

      {loading && <LoadingState />}
      {!loading && error && <ErrorState message={error} onRetry={loadAlerts} />}
      {!loading && !error && alerts.length === 0 && (
        <EmptyState
          title="No critical or high alerts found."
          message="Detected threats will appear here when risk reaches HIGH or CRITICAL."
        />
      )}

      {!loading && !error && alerts.length > 0 && (
        <div className="alerts-list">
          {alerts.map((alert) => (
            <Link className="security-alert" key={alert.id} to={`/threat/${alert.id}`}>
              <div className={`alert-icon ${String(alert.severity).toLowerCase()}`}>
                <AlertTriangle size={20} />
              </div>
              <div>
                <strong>{formatAttackType(alert.attackType) || "Unknown attack"}</strong>
                <p>{alert.endpoint || "Unknown endpoint"} from {alert.sourceIp || "Unknown IP"}</p>
              </div>
              <RiskBadge score={alert.riskScore} severity={alert.severity} />
              <span className="alert-time">
                <Bell size={14} />
                {formatTime(alert.timestamp)}
              </span>
            </Link>
          ))}
        </div>
      )}
    </main>
  );
}

export default AlertsPage;
