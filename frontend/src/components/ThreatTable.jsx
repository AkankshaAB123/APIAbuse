import { Link } from "react-router-dom";
import RiskBadge from "./RiskBadge";
import { formatAttackType } from "../data/attackTypes";

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
              <th>Attack Type</th>
              <th>Risk</th>
              <th>Action</th>
              <th>Investigate</th>
            </tr>
          </thead>

          <tbody>

            {threats.length === 0 ? (

              <tr>
                <td colSpan="6" className="no-threats">
                  No threats found.
                </td>
              </tr>

            ) : (

              threats.map((threat) => (
                <tr key={threat.id}>

                  <td>
                    {threat.timestamp}
                  </td>

                  <td>
                    {threat.sourceIp}
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
