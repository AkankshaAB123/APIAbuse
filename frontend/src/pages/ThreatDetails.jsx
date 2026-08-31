import { useParams, Link } from "react-router-dom";
import { threats } from "../data/mockData";

function ThreatDetails() {
  const { id } = useParams();

  const threat = threats.find(
    (item) => item.id === id
  );

  if (!threat) {
    return (
      <div className="details-page">
        <h1>Threat Not Found</h1>

        <Link to="/">
          ← Back to Dashboard
        </Link>
      </div>
    );
  }

  return (
    <div className="details-page">

      <div className="details-header">
        <div>
          <Link to="/" className="back-link">
            ← Back to Dashboard
          </Link>

          <h1>Threat Details</h1>
        </div>

        <span className="threat-id">
          {threat.id}
        </span>
      </div>


      {/* Main Information */}
      <div className="details-grid">

        <div className="detail-card">
          <span className="detail-label">
            Attack Type
          </span>

          <strong className="detail-value">
            {threat.attackType}
          </strong>
        </div>


        <div className="detail-card">
          <span className="detail-label">
            Source IP
          </span>

          <strong className="detail-value">
            {threat.sourceIp}
          </strong>
        </div>


        <div className="detail-card">
          <span className="detail-label">
            Risk Score
          </span>

          <strong className="detail-value risk-value">
            {threat.riskScore}/100
          </strong>
        </div>


        <div className="detail-card">
          <span className="detail-label">
            Severity
          </span>

          <strong className="detail-value">
            {threat.severity}
          </strong>
        </div>


        <div className="detail-card">
          <span className="detail-label">
            Action Taken
          </span>

          <strong className="detail-value">
            {threat.action}
          </strong>
        </div>


        <div className="detail-card">
          <span className="detail-label">
            Detection Time
          </span>

          <strong className="detail-value">
            {threat.timestamp}
          </strong>
        </div>

      </div>


      {/* Evidence */}
      <div className="information-card">

        <h2>Detection Information</h2>

        <div className="information-row">
          <span>Detection Source</span>
          <strong>AI Threat Detection</strong>
        </div>

        <div className="information-row">
          <span>Confidence</span>
          <strong>
            {Math.round(threat.riskScore * 0.98)}%
          </strong>
        </div>

        <div className="information-row">
          <span>Status</span>
          <strong>Detected</strong>
        </div>

      </div>


      {/* AI Analysis - placeholder for later */}
      <div className="information-card">

        <h2>AI Analysis</h2>

        <p className="placeholder-text">
          AI-powered threat analysis will appear here
          after the RAG/LLM module is integrated.
        </p>

      </div>


      {/* Mitigation */}
      <div className="information-card">

        <h2>Mitigation</h2>

        <p>
          Recommended action:
          <strong> {threat.action}</strong>
        </p>

      </div>

    </div>
  );
}

export default ThreatDetails;