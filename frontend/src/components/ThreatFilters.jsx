function ThreatFilters({
  attackType,
  severity,
  action,
  onAttackTypeChange,
  onSeverityChange,
  onActionChange,
  onReset
}) {
  return (
    <div className="filters">

      <div className="filter-group">
        <label>Attack Type</label>

        <select
          value={attackType}
          onChange={(e) => onAttackTypeChange(e.target.value)}
        >
          <option value="ALL">All Attacks</option>
          <option value="DoS">DoS</option>
          <option value="Port Scan">Port Scan</option>
          <option value="Brute Force">Brute Force</option>
          <option value="API Abuse">API Abuse</option>
          <option value="Normal">Normal</option>
        </select>
      </div>

      <div className="filter-group">
        <label>Severity</label>

        <select
          value={severity}
          onChange={(e) => onSeverityChange(e.target.value)}
        >
          <option value="ALL">All Severities</option>
          <option value="LOW">Low</option>
          <option value="MEDIUM">Medium</option>
          <option value="HIGH">High</option>
          <option value="CRITICAL">Critical</option>
        </select>
      </div>

      <div className="filter-group">
        <label>Action</label>

        <select
          value={action}
          onChange={(e) => onActionChange(e.target.value)}
        >
          <option value="ALL">All Actions</option>
          <option value="ALLOW">Allow</option>
          <option value="ALERT">Alert</option>
          <option value="RATE LIMIT">Rate Limit</option>
          <option value="BLOCK">Block</option>
        </select>
      </div>

      <button
        className="reset-button"
        onClick={onReset}
      >
        Reset
      </button>

    </div>
  );
}

export default ThreatFilters;