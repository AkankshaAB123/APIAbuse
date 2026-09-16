import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  Clock,
  Radar,
  ShieldAlert,
  ShieldCheck,
  Target,
} from "lucide-react";
import IncidentTable from "../components/IncidentTable";
import RiskBadge from "../components/RiskBadge";
import { ErrorState, LoadingState } from "../components/States";
import { formatAttackType } from "../data/attackTypes";
import { getStatistics, getThreats } from "../services/api";

function valueOrNA(value) {
  if (value === undefined || value === null || value === "") {
    return "N/A";
  }

  return typeof value === "object" ? JSON.stringify(value) : value;
}

function formatTimestamp(timestamp) {
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime())
    ? "N/A"
    : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function classificationText(threat) {
  const classification = threat?.classification || threat?.labIncident?.classification;

  if (!classification) {
    return "N/A";
  }

  return [
    classification.level1,
    classification.level2,
    classification.level3,
  ]
    .filter(Boolean)
    .join(" -> ");
}

function lifecycleStates(threat) {
  const lifecycle = threat?.labIncident?.lifecycle;

  if (Array.isArray(lifecycle?.states)) {
    return lifecycle.states;
  }

  if (Array.isArray(lifecycle)) {
    return lifecycle;
  }

  return [];
}

function targetText(threat) {
  return (
    threat?.endpoint ||
    threat?.labIncident?.attack?.target ||
    threat?.labIncident?.target?.endpoint ||
    threat?.labIncident?.request?.endpoint
  );
}

function impactSummary(threat) {
  const impact = threat?.labIncident?.impact;

  if (!impact) {
    return threat?.impactObserved ? "Impact observed" : "N/A";
  }

  if (impact.evidence) {
    return typeof impact.evidence === "string"
      ? impact.evidence
      : JSON.stringify(impact.evidence);
  }

  return impact.observed ? "Impact observed" : "Impact not observed";
}

function latestHighRiskIncident(threats) {
  return threats.find((threat) =>
    ["CRITICAL", "HIGH"].includes(String(threat.severity || "").toUpperCase())
  );
}

function LiveSecurityDashboard() {
  const [statistics, setStatistics] = useState(null);
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const loadLiveData = async ({ quiet = false } = {}) => {
    try {
      if (quiet) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setError("");

      const [stats, threatData] = await Promise.all([
        getStatistics(),
        getThreats(),
      ]);

      setStatistics(stats);
      setThreats(Array.isArray(threatData) ? threatData : []);
    } catch (err) {
      setError(err.message || "Unable to reach ThreatGuard backend.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadLiveData();

    const timer = window.setInterval(() => {
      if (!document.hidden) {
        loadLiveData({ quiet: true });
      }
    }, 8000);

    return () => window.clearInterval(timer);
  }, []);

  const summary = useMemo(() => {
    const mitigated = threats.filter((threat) =>
      ["BLOCKED", "REJECTED", "RATE_LIMITED", "MITIGATED"].includes(
        String(
          threat.mitigationResult ||
          threat.finalStatus ||
          threat.labIncident?.status ||
          ""
        ).toUpperCase()
      )
    ).length;

    const critical = threats.filter((threat) => threat.severity === "CRITICAL").length;
    const high = threats.filter((threat) => threat.severity === "HIGH").length;
    const latest = threats[0] || null;

    return {
      total: Number(statistics?.totalThreats ?? threats.length ?? 0),
      active: threats.filter((threat) =>
        ["ATTACKING", "DETECTED", "MITIGATING"].includes(
          String(threat.labIncident?.status || "").toUpperCase()
        )
      ).length,
      critical,
      high,
      mitigated,
      latest,
      alert: latestHighRiskIncident(threats),
    };
  }, [statistics, threats]);

  if (loading) {
    return (
      <main className="page-content">
        <LoadingState message="Loading live SOC incidents from MongoDB..." />
      </main>
    );
  }

  return (
    <main className="page-content">
      <div className="page-header">
        <div>
          <div className="page-kicker">ENTERPRISE SOC</div>
          <h1>Live Incident Command Center</h1>
          <p>
            Watch controlled lab attacks become detected, risk-scored,
            mitigated, and stored as real ThreatGuard incidents.
          </p>
        </div>

        <div className="enterprise-status">
          <span className="status-dot"></span>
          {refreshing ? "REFRESHING" : "LIVE POLLING"}
        </div>
      </div>

      {error && (
        <ErrorState
          title="Unable to load live incidents"
          message={error}
          onRetry={() => loadLiveData()}
        />
      )}

      {summary.alert && (
        <section className="live-alert-banner">
          <div className="live-alert-icon">
            <ShieldAlert size={26} />
          </div>
          <div>
            <span>SECURITY ALERT</span>
            <h2>{formatAttackType(summary.alert.attackType)}</h2>
            <p>
              {classificationText(summary.alert)} from{" "}
              {valueOrNA(summary.alert.sourceIp || summary.alert.actualClientIp)}
              {" "}against {valueOrNA(targetText(summary.alert))}.
            </p>
          </div>
          <div className="live-alert-meta">
            <RiskBadge
              score={summary.alert.riskScore}
              severity={summary.alert.severity}
            />
            <Link className="secondary-action" to={`/threat/${summary.alert.id}`}>
              Investigate
            </Link>
          </div>
        </section>
      )}

      <section className="live-stat-grid">
        <div className="enterprise-stat-card">
          <div className="enterprise-stat-icon enterprise-blue"><Activity size={23} /></div>
          <div><span>Total Incidents</span><strong>{summary.total}</strong><small>MongoDB-backed records</small></div>
        </div>
        <div className="enterprise-stat-card">
          <div className="enterprise-stat-icon enterprise-orange"><Radar size={23} /></div>
          <div><span>Active / Recent</span><strong>{summary.active}</strong><small>Currently in lifecycle</small></div>
        </div>
        <div className="enterprise-stat-card">
          <div className="enterprise-stat-icon enterprise-red"><AlertTriangle size={23} /></div>
          <div><span>Critical / High</span><strong>{summary.critical + summary.high}</strong><small>{summary.critical} critical, {summary.high} high</small></div>
        </div>
        <div className="enterprise-stat-card">
          <div className="enterprise-stat-icon enterprise-green"><ShieldCheck size={23} /></div>
          <div><span>Mitigated</span><strong>{summary.mitigated}</strong><small>Blocked, rejected, or limited</small></div>
        </div>
      </section>

      {summary.latest && (
        <section className="enterprise-card live-incident-card">
          <div className="enterprise-card-header">
            <div>
              <h2>Latest Incident Lifecycle</h2>
              <p>
                {formatAttackType(summary.latest.attackType)} at{" "}
                {formatTimestamp(summary.latest.timestamp)}
              </p>
            </div>
            <Target size={21} />
          </div>

          <div className="latest-incident-grid">
            <div><span>Incident ID</span><strong>{summary.latest.id}</strong></div>
            <div><span>Source IP</span><strong>{valueOrNA(summary.latest.sourceIp || summary.latest.actualClientIp)}</strong></div>
            <div><span>Target</span><strong>{valueOrNA(targetText(summary.latest))}</strong></div>
            <div><span>Mitigation</span><strong>{valueOrNA(summary.latest.mitigationResult || summary.latest.action)}</strong></div>
            <div><span>Impact</span><strong>{impactSummary(summary.latest)}</strong></div>
            <div><span>Detection</span><strong>{valueOrNA(summary.latest.labIncident?.detection?.primary_detector || summary.latest.labIncident?.detection?.method)}</strong></div>
          </div>

          <div className="lifecycle-strip live-lifecycle">
            {lifecycleStates(summary.latest).length > 0 ? (
              lifecycleStates(summary.latest).map((state) => (
                <span key={state}>{state}</span>
              ))
            ) : (
              <span>Lifecycle not available</span>
            )}
          </div>

          <Link className="secondary-action" to={`/threat/${summary.latest.id}`}>
            Open Incident Details
          </Link>
        </section>
      )}

      <section className="enterprise-card">
        <div className="enterprise-card-header">
          <div>
            <h2>Incident History</h2>
            <p>
              Dynamic source, user, target, risk, mitigation, and status values
              returned by the backend.
            </p>
          </div>
          <Clock size={21} />
        </div>

        <IncidentTable incidents={threats} />
      </section>
    </main>
  );
}

export default LiveSecurityDashboard;
