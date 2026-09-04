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

export { LoadingState, ErrorState, EmptyState };
