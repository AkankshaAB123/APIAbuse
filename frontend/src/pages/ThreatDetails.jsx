import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Bot, Clock, ShieldAlert, Activity, Server, Smartphone, Info, AlertTriangle, ShieldCheck, Database, Fingerprint, FileText } from "lucide-react";
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
  const labIncident = document.lab_incident || null;
  const labAttack = labIncident?.attack || {};
  const labImpact = labIncident?.impact || {};
  const labMitigation = labIncident?.mitigation || {};
  const request = labAttack.request || document.request || {};
  const identity = document.identity || {};
  const sourceIp =
    labAttack.actual_client_ip ||
    labAttack.source_ip ||
    document.network?.source_ip ||
    document.source_ip;
  const syntheticSourceIp =
    labAttack.actual_client_ip &&
    labAttack.source_ip &&
    labAttack.source_ip !== labAttack.actual_client_ip
      ? labAttack.source_ip
      : null;

  return {
    eventId: document.event_id || processing.event_id,
    timestamp: document.timestamp || labIncident?.lifecycle?.timestamps?.ATTACKING,
    sourceIp,
    syntheticSourceIp,
    userId:
      identity.user_id ||
      labAttack.attacker ||
      document.user_id ||
      "Unauthenticated",
    authStatus:
      labAttack.authentication ||
      (identity.is_authenticated ? "Authenticated" : "Unauthenticated"),
    targetUser: labAttack.target_user,
    targetResource: labAttack.requested_resource,
    domain:
      document.domain ||
      processing.ai_analysis?.domain ||
      processing.detector_results?.find((d) => d.detected)?.domain ||
      processing.detector_results?.[0]?.domain ||
      labIncident?.classification?.level1 ||
      "API",
    deviceSource:
      document.endpoint?.hostname ||
      document.endpoint?.device ||
      (document.network?.user_agent ? document.network.user_agent.split(" ")[0] : null) ||
      (labAttack.user_agent ? labAttack.user_agent.split(" ")[0] : null) ||
      "Standard Client",
    endpoint: labAttack.target_endpoint || request.endpoint || document.endpoint,
    method: labAttack.method || request.method || document.method,
    request,
    labIncident,
    classification: labIncident?.classification,
    impact: labImpact,
    finalStatus: labIncident?.status,
    mitigation: labMitigation,
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

function formatValue(value, fallback = "N/A") {
  if (value === null || value === undefined || value === "") {
    return fallback;
  }
  if (typeof value === "boolean") {
    return value ? "YES" : "NO";
  }
  return String(value);
}

function responseStatus(response) {
  return response?.status_code ?? response?.statusCode ?? "N/A";
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
    return aiContent.risk_assessment || "Risk is " + (threat.risk.risk_score ?? 0) + "/100 (" + (threat.risk.risk_level || "UNKNOWN") + ") based on detector matches, ML anomaly status, and the risk engine decision.";
  }

  if (question.includes("evidence") || question.includes("detector")) {
    return evidence.length
      ? evidence.join(" ")
      : aiContent.evidence || "No detector evidence was returned for this event.";
  }

  if (question.includes("fix") || question.includes("control") || question.includes("prevent")) {
    return aiContent.recommended_action || "Recommended action: " + threat.mitigationAction + ". Review authorization, input validation, rate limiting, and endpoint exposure for this API.";
  }

  if (question.includes("simple")) {
    return aiContent.threat_explanation || "" + (threat.risk.attack_types?.join(", ") || "This event") + " was flagged because the request matched one or more abuse detector rules.";
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
          // Keep backend error
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
    if (!question.trim() || !threat) return;
    setConversation((current) => [
      ...current,
      { question, answer: answerFromThreat(question, threat) },
    ]);
    setQuestion("");
  };

  if (loading) return <main className="page-content"><LoadingState /></main>;
  if (error) return <main className="page-content"><ErrorState message={error} onRetry={loadThreat} /></main>;
  if (!threat) return <main className="page-content"><EmptyState title="Threat not found." /></main>;

  const aiContent = threat.aiAnalysis?.ai_analysis || {};
  const retrievedDocuments = threat.aiAnalysis?.retrieved_documents || [];
  const aiAvailable = hasAiContent(aiContent);
  const detectedDetectors = threat.detectorResults.filter((detector) => detector.detected);
  const primaryDetector = threat.labIncident?.detection?.primary_detector || detectedDetectors[0] || null;
  const beforeMitigation = threat.impact?.target_response_before_mitigation;
  const afterMitigation = threat.mitigation?.post_mitigation_response;
  const lifecycle = threat.labIncident?.lifecycle;
  const syntheticEmail = threat.labIncident?.attack?.email;
  const attackTypesStr = threat.risk.attack_types?.map(formatAttackType).join(", ") || formatAttackType(threat.aiAnalysis?.attack_type) || "Unknown";

  return (
    <main className="page-content threat-details-view">
      <div className="soc-header">
        <div className="soc-header-content">
          <Link to="/threats" className="back-link">
            <ArrowLeft size={16} /> Threats
          </Link>
          <div className="soc-title-row">
            <ShieldAlert size={28} className="title-icon risk-high" />
            <div>
              <h1>Threat Investigation</h1>
              <p className="soc-subtitle">{threat.eventId} | {formatTimestamp(threat.timestamp)}</p>
            </div>
          </div>
        </div>
        <div className="soc-header-actions">
          <RiskBadge score={threat.risk.risk_score ?? 0} severity={threat.risk.risk_level || "LOW"} />
          <div className={"status-badge "}>
            {threat.mitigation?.result || threat.finalStatus || threat.mitigationAction}
          </div>
        </div>
      </div>

      <div className="soc-grid layout-3-col">

        {/* LEFT COLUMN: Summary & Context */}
        <div className="soc-grid-col">
          <section className="soc-card">
            <div className="soc-card-header">
              <Info size={18} />
              <h2>Threat Summary</h2>
            </div>
            <div className="soc-card-body">
              <div className="data-row"><span>Attack Type</span><strong>{attackTypesStr}</strong></div>
              <div className="data-row"><span>Domain</span><strong>{threat.domain || "API"}</strong></div>
              <div className="data-row"><span>Severity</span><strong>{threat.risk.risk_level || "LOW"}</strong></div>
              <div className="data-row"><span>Confidence</span><strong>{primaryDetector ? Math.round((primaryDetector.confidence || 0) * 100) + "%" : "N/A"}</strong></div>
              <div className="data-row"><span>Status</span><strong>{threat.mitigation?.result || threat.finalStatus || threat.mitigationAction}</strong></div>
            </div>
          </section>

          <section className="soc-card">
            <div className="soc-card-header">
              <Smartphone size={18} />
              <h2>Device / Client</h2>
            </div>
            <div className="soc-card-body">
              <div className="data-row"><span>Device</span><strong>{threat.deviceSource}</strong></div>
              <div className="data-row"><span>Source IP</span><strong>{threat.sourceIp || "Unknown"}</strong></div>
              {threat.syntheticSourceIp && (
                <div className="data-row"><span>Synthetic Source</span><strong>{threat.syntheticSourceIp}</strong></div>
              )}
              <div className="data-row"><span>User Auth</span><strong>{formatValue(threat.userId, "Unauthenticated")} &mdash; {threat.authStatus}</strong></div>
              <div className="data-row"><span>Endpoint</span><strong>{threat.method || "GET"} {threat.endpoint || "Unknown"}</strong></div>
            </div>
          </section>

          <section className="soc-card">
            <div className="soc-card-header">
              <Clock size={18} />
              <h2>Timeline</h2>
            </div>
            <div className="soc-card-body timeline-container">
              {lifecycle?.states?.length > 0 ? (
                lifecycle.states.map((state) => (
                  <div className="timeline-step" key={state}>
                    <div className="timeline-marker" />
                    <div className="timeline-content">
                      <span>{state}</span>
                      <small>{formatTimestamp(lifecycle.timestamps?.[state])}</small>
                    </div>
                  </div>
                ))
              ) : (
                ["Request received", "Detection started", "Threat identified", "Risk calculated", "Mitigation applied", "AI analysis completed"].map((item) => (
                  <div className="timeline-step" key={item}>
                    <div className="timeline-marker" />
                    <div className="timeline-content">
                      <span>{item}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </section>
        </div>

        {/* MIDDLE COLUMN: Detection & Risk */}
        <div className="soc-grid-col">
          <section className="soc-card">
            <div className="soc-card-header">
              <Activity size={18} />
              <h2>Detection</h2>
            </div>
            <div className="soc-card-body">
              <div className="data-row"><span>ML Anomaly</span><strong>{threat.risk.ml_anomaly ? "YES" : "NO"}</strong></div>
              <div className="data-row"><span>Detector Matches</span><strong>{detectedDetectors.length}</strong></div>

              {threat.mlResult && (
                <>
                  <div className="data-row"><span>XGBoost Prediction</span><strong>{threat.mlResult.detection?.prediction || "Unknown"}</strong></div>
                  <div className="data-row"><span>Isolation Forest</span><strong>{threat.mlResult.anomaly?.is_anomaly ? "ANOMALY" : "NORMAL"}</strong></div>
                </>
              )}

              {threat.detectorResults.map((detector) => (
                <div className={"detector-block "} key={detector.detector_id}>
                  <div className="detector-block-header">
                    <strong>{detector.detector_id}</strong>
                    <span>{detector.detected ? "DETECTED" : "CLEAR"} | {detector.severity}</span>
                  </div>
                  {(detector.evidence || []).map((item) => (
                    <div className="detector-evidence" key={item.code}>{item.message || item.code}</div>
                  ))}
                </div>
              ))}
            </div>
          </section>

          <section className="soc-card">
            <div className="soc-card-header">
              <AlertTriangle size={18} />
              <h2>Risk & Impact</h2>
            </div>
            <div className="soc-card-body">
              <div className="data-row"><span>Risk Score</span><strong>{threat.risk.risk_score ?? 0} / 100</strong></div>
              <div className="data-row"><span>Risk Reasons</span>
                <div className="reason-list">
                  {threat.risk.reasons?.length > 0 ?
                    threat.risk.reasons.map((r, i) => <span key={i} className="reason-badge">{r}</span>)
                    : "None provided"}
                </div>
              </div>

              {threat.labIncident && (
                <>
                  <div className="data-row"><span>Impact Observed</span><strong>{formatValue(threat.impact?.observed)}</strong></div>
                  <div className="data-row"><span>Impact Description</span><strong>{formatValue(threat.impact?.description)}</strong></div>
                </>
              )}
            </div>
          </section>

          <section className="soc-card">
            <div className="soc-card-header">
              <ShieldCheck size={18} />
              <h2>Mitigation</h2>
            </div>
            <div className="soc-card-body">
              <div className="data-row"><span>Recommended System Action</span><strong>{threat.mitigationAction}</strong></div>
              <div className="data-row"><span>Enforced</span><strong>{formatValue(threat.mitigation?.enforced)}</strong></div>
              <div className="data-row"><span>Final Action</span><strong>{threat.mitigation?.result || threat.mitigationAction}</strong></div>
              <div className="data-row"><span>Final HTTP Status</span><strong>{responseStatus(afterMitigation)}</strong></div>
            </div>
          </section>
        </div>

        {/* RIGHT COLUMN: AI & Knowledge */}
        <div className="soc-grid-col">
          <section className="soc-card ai-accent-card">
            <div className="soc-card-header ai-header">
              <div style={{display: "flex", alignItems: "center", gap: "8px"}}>
                <Bot size={18} />
                <h2>AI Analysis</h2>
              </div>
              {aiContent.confidence_level && (
                <span className={"ai-confidence "}>{aiContent.confidence_level}</span>
              )}
            </div>
            <div className="soc-card-body">
              {aiAvailable ? (
                <div className="ai-content-blocks">
                  <div className="ai-block">
                    <h4>Explanation</h4>
                    <p>{aiContent.threat_explanation}</p>
                  </div>
                  <div className="ai-block">
                    <h4>Evidence Evaluation</h4>
                    <p>{aiContent.evidence || "No additional AI evidence."}</p>
                  </div>
                  <div className="ai-block">
                    <h4>Risk Assessment</h4>
                    <p>{aiContent.risk_assessment || "No AI risk assessment."}</p>
                  </div>
                  <div className="ai-block">
                    <h4>Recommended Action</h4>
                    <p>{aiContent.recommended_action || "No AI recommendation."}</p>
                  </div>
                </div>
              ) : (
                <div className="ai-unavailable">AI analysis temporarily unavailable.</div>
              )}
            </div>
          </section>

          <section className="soc-card">
            <div className="soc-card-header">
              <Database size={18} />
              <h2>Retrieved Knowledge</h2>
            </div>
            <div className="soc-card-body">
              {retrievedDocuments.length > 0 ? (
                <div className="rag-documents">
                  {retrievedDocuments.map((doc, i) => (
                    <div className="rag-doc" key={i}>
                      <FileText size={14} />
                      <div className="rag-doc-info">
                        <strong>{doc.filename}</strong>
                        <span>Score: {doc.score}</span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-text">No context documents retrieved.</div>
              )}
            </div>
          </section>

          <section className="soc-card copilot-card">
            <div className="soc-card-header">
              <Bot size={18} />
              <h2>AI Copilot Q&A</h2>
            </div>
            <div className="soc-card-body">
              <div className="copilot-thread small-thread">
                {conversation.map((item, index) => (
                  <div className="copilot-message" key={index}>
                    <strong>{item.question}</strong>
                    <p>{item.answer}</p>
                  </div>
                ))}
              </div>
              <form className="copilot-inline-form" onSubmit={askQuestion}>
                <input
                  value={question}
                  onChange={(e) => setQuestion(e.target.value)}
                  placeholder="Ask about this threat..."
                />
                <button type="submit">Ask</button>
              </form>
            </div>
          </section>
        </div>
      </div>
    </main>
  );
}

export default ThreatDetails;
