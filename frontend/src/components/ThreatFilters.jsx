import { ATTACK_FILTER_OPTIONS } from "../data/attackTypes";

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
          {ATTACK_FILTER_OPTIONS.map((type) => (
            <option key={type.value} value={type.value}>
              {type.label}
            </option>
          ))}
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
          <option value="RATE_LIMIT">Rate Limit</option>
          <option value="MONITOR">Monitor</option>
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
