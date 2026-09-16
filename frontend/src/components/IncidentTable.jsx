import { Link } from "react-router-dom";
import RiskBadge from "./RiskBadge";
import { formatAttackType } from "../data/attackTypes";

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
  const classification = threat.classification || threat.labIncident?.classification;

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

function userText(threat) {
  return (
    threat.userId ||
    threat.labIncident?.attack?.requester ||
    threat.labIncident?.attack?.user ||
    threat.labIncident?.attack?.captured_username ||
    threat.labIncident?.attack?.authentication_status ||
    "Unauthenticated"
  );
}

function targetText(threat) {
  return (
    threat.endpoint ||
    threat.labIncident?.attack?.target ||
    threat.labIncident?.target?.endpoint ||
    threat.labIncident?.request?.endpoint
  );
}

function finalStatus(threat) {
  return (
    threat.mitigationResult ||
    threat.finalStatus ||
    threat.labIncident?.mitigation?.result ||
    threat.labIncident?.status ||
    threat.action
  );
}

function IncidentTable({ incidents }) {
  return (
    <div className="incident-table-wrap">
      <table className="incident-table">
        <thead>
          <tr>
            <th>Incident</th>
            <th>Time</th>
            <th>Source</th>
            <th>User / Auth</th>
            <th>Attack</th>
            <th>Classification</th>
            <th>Target</th>
            <th>Risk</th>
            <th>Mitigation</th>
            <th>Status</th>
          </tr>
        </thead>

        <tbody>
          {incidents.length === 0 ? (
            <tr>
              <td colSpan="10" className="no-threats">
                No lab incidents found.
              </td>
            </tr>
          ) : (
            incidents.map((threat) => (
              <tr key={threat.id}>
                <td>
                  <Link className="threat-link" to={`/threat/${threat.id}`}>
                    {threat.id}
                  </Link>
                </td>
                <td>{formatTimestamp(threat.timestamp)}</td>
                <td>
                  {valueOrNA(threat.sourceIp || threat.actualClientIp)}
                  {threat.syntheticSourceIp && (
                    <span className="table-subtext">
                      Lab: {threat.syntheticSourceIp}
                    </span>
                  )}
                </td>
                <td>{userText(threat)}</td>
                <td>{formatAttackType(threat.attackType)}</td>
                <td>{classificationText(threat)}</td>
                <td>
                  {valueOrNA(threat.method)} {valueOrNA(targetText(threat))}
                </td>
                <td>
                  <RiskBadge
                    score={threat.riskScore}
                    severity={threat.severity}
                  />
                </td>
                <td>{valueOrNA(threat.action)}</td>
                <td>{valueOrNA(finalStatus(threat))}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

export default IncidentTable;
