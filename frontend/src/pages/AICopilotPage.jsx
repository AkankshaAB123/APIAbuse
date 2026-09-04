import { Bot, ShieldAlert } from "lucide-react";
import { Link } from "react-router-dom";

function AICopilotPage() {
  return (
    <main className="page-content">
      <div className="page-header">
        <div>
          <div className="page-kicker">AI SECURITY</div>
          <h1>Security AI Copilot</h1>
          <p>Open any threat to ask context-aware questions using the threat's RAG and Gemini analysis.</p>
        </div>
      </div>

      <section className="information-card copilot-empty">
        <Bot size={34} />
        <h2>Threat-aware AI is available from Threat Details</h2>
        <p>
          ThreatGuard already receives Gemini analysis with RAG knowledge during event processing.
          Select a detected threat to inspect the AI explanation, evidence, risk assessment,
          recommended action, and retrieved documents.
        </p>
        <Link className="view-threat-button" to="/threats">
          <ShieldAlert size={16} />
          VIEW THREATS
        </Link>
      </section>
    </main>
  );
}

export default AICopilotPage;
