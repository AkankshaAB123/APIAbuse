function RiskBadge({ score, severity }) {
  const getRiskClass = () => {
    switch (severity) {
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
      <span className="risk-score">{score}</span>

      <span className="risk-severity">
        {severity}
      </span>
    </div>
  );
}

export default RiskBadge;