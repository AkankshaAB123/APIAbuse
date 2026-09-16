import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, Bell, Clock, ShieldAlert } from "lucide-react";
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

  const alerts = threats
    .map((doc) => {
      const processing = doc.processing || doc;
      const risk = processing.risk_assessment || doc.risk_assessment || {};
      const labIncident = doc.lab_incident;

      const domain =
        doc.domain ||
        processing.ai_analysis?.domain ||
        labIncident?.classification?.level1 ||
        "API";

      const status = labIncident?.status || processing.mitigation_action || "DETECTED";
      const evidence = doc.processing?.ai_analysis?.threat_explanation || doc.risk_assessment?.reasons?.join(" ") || "No detailed evidence available.";

      return {
        id: doc.event_id || processing.event_id,
        timestamp: doc.timestamp || labIncident?.lifecycle?.timestamps?.ATTACKING,
        attackType: risk.attack_types?.[0] || processing.ai_analysis?.attack_type,
        severity: risk.risk_level || "HIGH",
        riskScore: risk.risk_score ?? 0,
        domain: domain,
        status: status,
        evidence: evidence,
      };
    })
    .filter((alert) => alert.severity === "HIGH" || alert.severity === "CRITICAL")
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

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
            <Link className={"security-alert-card severity-" + String(alert.severity).toLowerCase()} key={alert.id} to={"/threat/" + alert.id}>
              <div className="alert-header">
                <div className="alert-title-row">
                  <ShieldAlert size={18} className="alert-icon" />
                  <strong>{formatAttackType(alert.attackType) || "Unknown Threat"}</strong>
                  <span className="alert-domain">{alert.domain}</span>
                </div>
                <RiskBadge score={alert.riskScore} severity={alert.severity} />
              </div>
              <div className="alert-body">
                <p className="alert-evidence">{alert.evidence}</p>
                <div className="alert-footer">
                  <span className="alert-time"><Clock size={12} /> {formatTime(alert.timestamp)}</span>
                  <span className="alert-status">{alert.status}</span>
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </main>
  );
}

export default AlertsPage;
