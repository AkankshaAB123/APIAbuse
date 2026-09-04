function LoadingState({ title = "Loading security intelligence..." }) {
  return (
    <div className="state-panel">
      <div className="state-spinner" />
      <strong>{title}</strong>
    </div>
  );
}

function ErrorState({ title = "Unable to reach ThreatGuard backend.", message, onRetry }) {
  return (
    <div className="state-panel state-error">
      <strong>{title}</strong>
      {message && <p>{message}</p>}
      {onRetry && (
        <button className="view-threat-button" onClick={onRetry}>
          RETRY
        </button>
      )}
    </div>
  );
}

function EmptyState({ title = "No threats found.", message }) {
  return (
    <div className="state-panel">
      <strong>{title}</strong>
      {message && <p>{message}</p>}
    </div>
  );
}

function AccessRestricted({ role = "Security Analyst" }) {
  return (
    <main className="page-content">
      <div className="access-restricted state-panel">
        <strong>Access Restricted</strong>
        <p>You do not have permission to access this security management feature.</p>
        <div className="information-row">
          <span>Current role</span>
          <strong>{role}</strong>
        </div>
        <a className="view-threat-button" href="/">
          Return to Dashboard
        </a>
      </div>
    </main>
  );
}

export { LoadingState, ErrorState, EmptyState, AccessRestricted };
