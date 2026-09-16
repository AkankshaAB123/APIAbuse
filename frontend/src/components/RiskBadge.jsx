function RiskBadge({ score, severity }) {
  const displayScore = typeof score === "object" ? JSON.stringify(score) : score;
  const displaySeverity = typeof severity === "object" ? JSON.stringify(severity) : severity;

  const getRiskClass = () => {
    switch (displaySeverity) {
      case "CRITICAL":
        return "risk-critical";

      case "HIGH":
        return "risk-high";

      case "MEDIUM":
        return "risk-medium";

      case "LOW":
        return "risk-low";

      default:
        return "risk-low";
    }
  };

  return (
    <div className={`risk-badge ${getRiskClass()}`}>
      <span className="risk-score">{displayScore ?? "N/A"}</span>

      <span className="risk-severity">
        {displaySeverity ?? "N/A"}
      </span>
    </div>
  );
}

export default RiskBadge;
