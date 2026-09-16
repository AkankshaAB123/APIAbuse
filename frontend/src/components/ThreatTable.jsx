import { Link } from "react-router-dom";
import RiskBadge from "./RiskBadge";
import { formatAttackType } from "../data/attackTypes";

function formatTimestamp(timestamp) {
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime())
    ? "N/A"
    : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function ThreatTable({ threats }) {
  return (
    <section className="threat-section">

      <div className="section-header">
        <h2>Recent Threats</h2>

        <span>
          {threats.length} events
        </span>
      </div>

      <div className="table-container">

        <table>

          <thead>
            <tr>
              <th>Time</th>
              <th>Source IP</th>
              <th>Target</th>
              <th>Attack Type</th>
              <th>Risk</th>
              <th>Action</th>
              <th>Status</th>
              <th>Investigate</th>
            </tr>
          </thead>

          <tbody>

            {threats.length === 0 ? (

              <tr>
                <td colSpan="8" className="no-threats">
                  No threats found.
                </td>
              </tr>

            ) : (

              threats.map((threat) => (
                <tr key={threat.id}>

                  <td>
                    {formatTimestamp(threat.timestamp)}
                  </td>

                  <td>
                    {threat.sourceIp || "N/A"}
                    {threat.syntheticSourceIp && (
                      <span className="table-subtext">
                        Lab source: {threat.syntheticSourceIp}
                      </span>
                    )}
                  </td>

                  <td>
                    <span>{threat.method || "GET"} {threat.endpoint || "N/A"}</span>
                    {threat.impactObserved !== undefined && (
                      <span className="table-subtext">
                        Impact: {threat.impactObserved ? "Observed" : "Not observed"}
                      </span>
                    )}
                  </td>

                  <td>
                    <Link
                      to={`/threat/${threat.id}`}
                      className="threat-link"
                    >
                      {formatAttackType(threat.attackType)}
                    </Link>
                  </td>

                  <td>
                    <RiskBadge
                      score={threat.riskScore}
                      severity={threat.severity}
                    />
                  </td>

                  <td>
                    <span className="action">
                      {threat.action}
                    </span>
                  </td>

                  <td>
                    {threat.mitigationResult || threat.finalStatus || "N/A"}
                  </td>

                  <td>
                    <Link
                      to={`/threat/${threat.id}`}
                      className="table-action-link"
                    >
                      VIEW
                    </Link>
                  </td>

                </tr>
              ))

            )}

          </tbody>

        </table>

      </div>

    </section>
  );
}

export default ThreatTable;
