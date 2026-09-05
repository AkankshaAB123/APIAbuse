import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Bot, Clock } from "lucide-react";
import RiskBadge from "../components/RiskBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
import { getThreatById } from "../services/api";
import { formatAttackType } from "../data/attackTypes";

const suggestedQuestions = [
  "Why was this attack detected?",
  "Why is the risk score this high?",
  "What evidence triggered the detector?",
  "How can I fix this vulnerability?",
  "What security control should prevent this?",
  "What OWASP API Security category does this relate to?",
  "What would happen if this attack was not blocked?",
  "Explain this attack in simple terms.",
];

function normalizeThreat(document) {
  const processing = document.processing || document;
  const risk = processing.risk_assessment || document.risk_assessment || {};

  return {
    eventId: document.event_id || processing.event_id,
    timestamp: document.timestamp,
    sourceIp: document.network?.source_ip || document.source_ip,
    userId: document.identity?.user_id || document.user_id,
    endpoint: document.request?.endpoint || document.endpoint,
    method: document.request?.method || document.method,
    detectorResults: processing.detector_results || document.detector_results || [],
    mlResult: processing.ml_result || document.ml_result,
    risk,
    mitigationAction: processing.mitigation_action || document.mitigation_action || "ALLOW",
    aiAnalysis: processing.ai_analysis || document.ai_analysis,
  };
}

function formatTimestamp(timestamp) {
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime())
    ? "Unknown"
    : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" });
}

function hasAiContent(aiContent) {
  return Boolean(
    aiContent?.threat_explanation ||
    aiContent?.evidence ||
    aiContent?.risk_assessment ||
    aiContent?.recommended_action
  );
}

function answerFromThreat(question, threat) {
  const aiContent = threat.aiAnalysis?.ai_analysis || {};
  const evidence = threat.detectorResults
    .filter((detector) => detector.detected)
    .flatMap((detector) =>
      (detector.evidence || []).map((item) => item.message || item.code)
    );

  if (question.includes("risk score")) {
    return aiContent.risk_assessment || `Risk is ${threat.risk.risk_score ?? 0}/100 (${threat.risk.risk_level || "UNKNOWN"}) based on detector matches, ML anomaly status, and the risk engine decision.`;
  }

  if (question.includes("evidence") || question.includes("detector")) {
    return evidence.length
      ? evidence.join(" ")
      : aiContent.evidence || "No detector evidence was returned for this event.";
  }

  if (question.includes("fix") || question.includes("control") || question.includes("prevent")) {
    return aiContent.recommended_action || `Recommended action: ${threat.mitigationAction}. Review authorization, input validation, rate limiting, and endpoint exposure for this API.`;
  }

  if (question.includes("simple")) {
    return aiContent.threat_explanation || `${threat.risk.attack_types?.join(", ") || "This event"} was flagged because the request matched one or more abuse detector rules.`;
  }

  return (
    aiContent.threat_explanation ||
    threat.risk.reasons?.join(" ") ||
    "The event was processed successfully, but Gemini did not return a detailed explanation for this threat."
  );
}

function ThreatDetails() {
  const { id } = useParams();
  const [rawThreat, setRawThreat] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [question, setQuestion] = useState(suggestedQuestions[0]);
  const [conversation, setConversation] = useState([]);

  const loadThreat = useCallback(async () => {
    try {
      setLoading(true);
      setError("");
      const data = await getThreatById(id);
      setRawThreat(data);
    } catch (err) {
      const storedThreat = localStorage.getItem("latestThreat");

      if (storedThreat) {
        try {
          const parsedThreat = JSON.parse(storedThreat);
          if (parsedThreat.event_id === id) {
            setRawThreat(parsedThreat);
            return;
          }
        } catch {
          // Keep the backend error below.
        }
      }

      setError(err.message || "Unable to load threat details.");
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    loadThreat();
  }, [loadThreat]);

  const threat = useMemo(
    () => (rawThreat ? normalizeThreat(rawThreat) : null),
    [rawThreat]
  );

  const askQuestion = (event) => {
    event.preventDefault();

    if (!question.trim() || !threat) {
      return;
    }

    setConversation((current) => [
      ...current,
      {
        question,
        answer: answerFromThreat(question, threat),
      },
    ]);
    setQuestion("");
  };

  if (loading) {
    return <main className="page-content"><LoadingState /></main>;
  }

  if (error) {
    return <main className="page-content"><ErrorState message={error} onRetry={loadThreat} /></main>;
  }

  if (!threat) {
    return <main className="page-content"><EmptyState title="Threat not found." /></main>;
  }

  const aiContent = threat.aiAnalysis?.ai_analysis || {};
  const retrievedDocuments = threat.aiAnalysis?.retrieved_documents || [];
  const aiAvailable = hasAiContent(aiContent);
  const detectedDetectors = threat.detectorResults.filter((detector) => detector.detected);

  return (
    <main className="details-page">
      <div className="details-header">
        <div>
          <Link to="/threats" className="back-link">
            <ArrowLeft size={16} />
            Threats
          </Link>
          <h1>Threat Investigation</h1>
          <p>Detector evidence, ML/risk assessment, AI explanation, RAG knowledge, and mitigation.</p>
        </div>
        <span className="threat-id">{threat.eventId}</span>
      </div>

      <section className="details-grid">
        <div className="detail-card"><span className="detail-label">Attack Type</span><strong className="detail-value">{threat.risk.attack_types?.map(formatAttackType).join(", ") || formatAttackType(threat.aiAnalysis?.attack_type) || "Unknown"}</strong></div>
        <div className="detail-card"><span className="detail-label">Timestamp</span><strong className="detail-value">{formatTimestamp(threat.timestamp)}</strong></div>
        <div className="detail-card"><span className="detail-label">Source IP</span><strong className="detail-value">{threat.sourceIp || "Unknown"}</strong></div>
        <div className="detail-card"><span className="detail-label">Endpoint</span><strong className="detail-value">{threat.method || "GET"} {threat.endpoint || "Unknown"}</strong></div>
        <div className="detail-card"><span className="detail-label">Risk Score</span><RiskBadge score={threat.risk.risk_score ?? 0} severity={threat.risk.risk_level || "LOW"} /></div>
        <div className="detail-card"><span className="detail-label">Action</span><strong className="detail-value">{threat.mitigationAction}</strong></div>
      </section>

      <section className="information-card">
        <h2>Detection Evidence</h2>
        {threat.risk.reasons?.length > 0 ? (
          <div className="ai-evidence-list">
            {threat.risk.reasons.map((reason, index) => (
              <div className="evidence-item" key={`${reason}-${index}`}>{reason}</div>
            ))}
          </div>
        ) : (
          <p className="placeholder-text">No risk reasons were returned for this event.</p>
        )}
      </section>

      <section className="information-card">
        <h2>Detector Results</h2>
        <div className="detector-grid">
          {threat.detectorResults.map((detector) => (
            <div className={`detector-card ${detector.detected ? "detected" : ""}`} key={detector.detector_id}>
              <strong>{detector.detector_id}</strong>
              <span>{detector.detected ? "DETECTED" : "CLEAR"} | {detector.severity} | {Math.round((detector.confidence || 0) * 100)}%</span>
              {(detector.evidence || []).map((item) => (
                <p key={item.code}>{item.message || item.code}</p>
              ))}
            </div>
          ))}
        </div>
      </section>

      <section className="information-card">
        <h2>ML / Risk Analysis</h2>
        <div className="information-row"><span>Threat Detected</span><strong>{threat.risk.threat_detected ? "YES" : "NO"}</strong></div>
        <div className="information-row"><span>Detector Matches</span><strong>{detectedDetectors.length}</strong></div>
        <div className="information-row"><span>ML Anomaly</span><strong>{threat.risk.ml_anomaly ? "YES" : "NO"}</strong></div>
        {threat.mlResult && (
          <>
            <div className="information-row"><span>XGBoost Prediction</span><strong>{threat.mlResult.detection?.prediction || "Unknown"}</strong></div>
            <div className="information-row"><span>ML Confidence</span><strong>{Math.round((threat.mlResult.detection?.confidence || 0) * 100)}%</strong></div>
            <div className="information-row"><span>Isolation Forest</span><strong>{threat.mlResult.anomaly?.is_anomaly ? "ANOMALY" : "NORMAL"}</strong></div>
          </>
        )}
      </section>

      <section className="information-card ai-analysis-card">
        <div className="ai-analysis-header">
          <div>
            <h2>AI Analysis</h2>
            <p>RAG + Gemini Security Intelligence</p>
          </div>
          <span className={aiAvailable ? "ai-badge" : "ai-badge muted"}>{aiAvailable ? "AI POWERED" : "UNAVAILABLE"}</span>
        </div>

        {aiAvailable ? (
          <div className="ai-section-grid">
            <div className="ai-section"><h3>Threat Explanation</h3><p>{aiContent.threat_explanation}</p></div>
            <div className="ai-section"><h3>Evidence</h3><p>{aiContent.evidence || "No additional AI evidence provided."}</p></div>
            <div className="ai-section"><h3>Risk Assessment</h3><p>{aiContent.risk_assessment || "No additional AI risk assessment provided."}</p></div>
            <div className="ai-section"><h3>Recommended Action</h3><p>{aiContent.recommended_action || "No AI recommendation provided."}</p></div>
          </div>
        ) : (
          <div className="ai-status-warning">
            AI analysis temporarily unavailable. Your threat detection results are still available.
          </div>
        )}
      </section>

      <section className="information-card">
        <h2>RAG Knowledge</h2>
        {retrievedDocuments.length > 0 ? (
          <div className="retrieved-documents">
            {retrievedDocuments.map((document, index) => (
              <div className="retrieved-document" key={`${document.filename}-${index}`}>
                <span>{document.filename}</span>
                <span>Similarity: {document.score}</span>
              </div>
            ))}
          </div>
        ) : (
          <p className="placeholder-text">No retrieved RAG documents were returned for this threat.</p>
        )}
      </section>

      <section className="information-card">
        <h2>Mitigation</h2>
        <div className="information-row"><span>Recommended System Action</span><strong>{threat.mitigationAction}</strong></div>
        <div className="information-row"><span>Risk-Based Decision</span><strong>{threat.risk.risk_level || "UNKNOWN"}</strong></div>
        <div className="information-row"><span>Final Action</span><strong>{threat.mitigationAction}</strong></div>
      </section>

      <section className="information-card">
        <h2>Attack Timeline</h2>
        <div className="timeline-list">
          {["Request received", "Detection started", "Threat identified", "Risk calculated", "Mitigation applied", "AI analysis completed"].map((item) => (
            <div className="timeline-item" key={item}>
              <Clock size={15} />
              <span>{item}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="information-card ai-copilot-panel">
        <div className="ai-analysis-header">
          <div>
            <h2>AI Security Copilot</h2>
            <p>Ask about this threat using its existing detector, risk, RAG, and Gemini context.</p>
          </div>
          <Bot size={22} />
        </div>

        <div className="suggested-question-list">
          {suggestedQuestions.map((item) => (
            <button type="button" key={item} onClick={() => setQuestion(item)}>
              {item}
            </button>
          ))}
        </div>

        <form className="copilot-form" onSubmit={askQuestion}>
          <input
            value={question}
            onChange={(event) => setQuestion(event.target.value)}
            placeholder="Ask anything about this threat..."
          />
          <button className="primary-action" type="submit">ASK AI</button>
        </form>

        {conversation.length > 0 && (
          <div className="copilot-thread">
            {conversation.map((item, index) => (
              <div className="copilot-message" key={`${item.question}-${index}`}>
                <strong>{item.question}</strong>
                <p>{item.answer}</p>
              </div>
            ))}
          </div>
        )}
      </section>
    </main>
  );
}

export default ThreatDetails;
