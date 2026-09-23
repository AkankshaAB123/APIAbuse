import { useState, useEffect, useCallback } from "react";
import { Bot, ShieldAlert, FileText, Send, Sparkles, AlertTriangle, Search, BookOpen, Activity, Crosshair } from "lucide-react";
import { Link } from "react-router-dom";
import { getThreats, getThreatById } from "../services/api";
import { formatAttackType } from "../data/attackTypes";
import { LoadingState } from "../components/States";
import RiskBadge from "../components/RiskBadge";

const SUGGESTED_QUESTIONS = [
  "Explain this threat in simple terms",
  "What detector evidence was triggered?",
  "What is the risk score and impact?",
  "How should we mitigate or fix this issue?",
];

function answerFromThreat(questionText, threat) {
  const q = questionText.toLowerCase();
  const processing = threat.processing || threat;
  const aiContent = processing.ai_analysis?.ai_analysis || {};
  const detectorResults = processing.detector_results || [];
  const evidence = detectorResults
    .filter((d) => d.detected)
    .flatMap((d) => (d.evidence || []).map((e) => e.message || e.code));

  if (q.includes("risk score") || q.includes("impact")) {
    return (
      aiContent.risk_assessment ||
      "Risk score is " + (processing.risk_assessment?.risk_score ?? 0) + "/100 (" + (processing.risk_assessment?.risk_level || "UNKNOWN") + ")."
    );
  }

  if (q.includes("evidence") || q.includes("detector")) {
    return evidence.length > 0
      ? evidence.join("; ")
      : aiContent.evidence || "No specific detector evidence recorded.";
  }

  if (q.includes("mitigate") || q.includes("fix") || q.includes("prevent")) {
    return (
      aiContent.recommended_action ||
      "Enforced action: " + (processing.mitigation_action || "ALLOW") + ". Inspect access controls, rate limiting, and input validation."
    );
  }

  if (q.includes("simple")) {
    return (
      aiContent.threat_explanation ||
      "This activity was flagged because it matched security abuse detection rules on " + (processing.request?.endpoint || "the target endpoint") + "."
    );
  }

  return (
    aiContent.threat_explanation ||
    "Threat event processed with RAG intelligence. See detailed explanation above."
  );
}

function AICopilotPage() {
  const [threats, setThreats] = useState([]);
  const [selectedThreatId, setSelectedThreatId] = useState("");
  const [threatDetails, setThreatDetails] = useState(null);
  const [loadingList, setLoadingList] = useState(true);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [chatMessages, setChatMessages] = useState([]);
  const [inputQuestion, setInputQuestion] = useState("");

  useEffect(() => {
    async function loadThreatList() {
      try {
        setLoadingList(true);
        const data = await getThreats();
        const list = Array.isArray(data) ? data : [];
        setThreats(list);
        if (list.length > 0) {
          setSelectedThreatId(list[0].id);
        }
      } catch {
        setThreats([]);
      } finally {
        setLoadingList(false);
      }
    }
    loadThreatList();
  }, []);

  const loadDetails = useCallback(async (id) => {
    if (!id) return;
    try {
      setLoadingDetails(true);
      const detail = await getThreatById(id);
      setThreatDetails(detail);
      setChatMessages([]);
    } catch {
      setThreatDetails(null);
    } finally {
      setLoadingDetails(false);
    }
  }, []);

  useEffect(() => {
    if (selectedThreatId) {
      loadDetails(selectedThreatId);
    }
  }, [selectedThreatId, loadDetails]);

  const handleAsk = (e) => {
    e.preventDefault();
    if (!inputQuestion.trim() || !threatDetails) return;
    const answer = answerFromThreat(inputQuestion, threatDetails);
    setChatMessages((prev) => [...prev, { q: inputQuestion, a: answer }]);
    setInputQuestion("");
  };

  const handleSuggest = (q) => {
    if (!threatDetails) return;
    const answer = answerFromThreat(q, threatDetails);
    setChatMessages((prev) => [...prev, { q, a: answer }]);
  };

  const aiAnalysis = threatDetails?.processing?.ai_analysis || threatDetails?.ai_analysis || {};
  const aiContent = aiAnalysis.ai_analysis || {};
  const retrievedDocs = aiAnalysis.retrieved_documents || [];
  const detectors = threatDetails?.processing?.detector_results || threatDetails?.detector_results || [];
  const detectedCount = detectors.filter((d) => d.detected).length;
  const mlResult = threatDetails?.processing?.ml_result || threatDetails?.ml_result;
  const attackType = threatDetails?.processing?.risk_assessment?.attack_types?.[0] || aiAnalysis.attack_type || "Unknown Threat";

  return (
    <main className="page-content">
      <div className="soc-header">
        <div className="soc-header-content">
          <div className="soc-title-row">
            <Bot size={28} className="title-icon" style={{color: "#8b5cf6"}} />
            <div>
              <h1>AI Security Copilot</h1>
              <p className="soc-subtitle">Context-aware reasoning across detected events, retrieved RAG knowledge, and Gemini LLM analysis.</p>
            </div>
          </div>
        </div>
      </div>

      <section className="soc-card" style={{ marginBottom: "24px" }}>
        <div className="soc-card-header">
          <Search size={18} />
          <h2>Select Incident Context</h2>
        </div>
        <div className="soc-card-body" style={{ display: "flex", flexWrap: "wrap", gap: "16px", alignItems: "center", justifyContent: "space-between" }}>
          {loadingList ? (
            <span style={{ color: "#64748b", fontSize: "13px" }}>Loading threats...</span>
          ) : threats.length === 0 ? (
            <span style={{ color: "#64748b", fontSize: "13px" }}>No threats recorded yet.</span>
          ) : (
            <select
              className="filter-select"
              value={selectedThreatId}
              onChange={(e) => setSelectedThreatId(e.target.value)}
              style={{ minWidth: "260px", maxWidth: "420px", flex: "1 1 260px" }}
            >
              {threats.map((t) => (
                <option key={t.id} value={t.id}>
                  {formatAttackType(t.attackType)} - {t.id?.slice(0, 8)}...
                </option>
              ))}
            </select>
          )}
          {threatDetails && (
            <div style={{ display: "flex", flexWrap: "wrap", gap: "12px", alignItems: "center", minWidth: 0 }}>
              <span className="alert-domain">{threatDetails.domain || "API"}</span>
              <RiskBadge
                score={threatDetails.processing?.risk_assessment?.risk_score || 0}
                severity={threatDetails.processing?.risk_assessment?.risk_level || "LOW"}
              />
              <Link to={"/threat/" + selectedThreatId} className="sidebar-link active" style={{ padding: "6px 14px", whiteSpace: "nowrap" }}>
                View Full Details
              </Link>
            </div>
          )}
        </div>
      </section>

      {loadingDetails ? (
        <LoadingState />
      ) : !threatDetails ? (
        <div className="empty-text" style={{textAlign: "center", padding: "40px"}}>Select a threat to begin analysis.</div>
      ) : (
        <div className="soc-grid layout-3-col">
          {/* LEFT: SIGNAL EVIDENCE */}
          <div className="soc-grid-col">
            <section className="soc-card">
              <div className="soc-card-header">
                <Crosshair size={18} />
                <h2>Rule Detection</h2>
              </div>
              <div className="soc-card-body">
                <div className="data-row">
                  <span>Matched Detectors</span>
                  <strong>{detectedCount}</strong>
                </div>
                {detectors.map((d, i) => (
                  <div key={i} className={"detector-block " + (d.detected ? "detected" : "")}>
                    <div className="detector-block-header">
                      <strong>{d.detector_id}</strong>
                      <span className={d.detected ? "status-pill-detected" : "status-pill-clear"}>
                        {d.detected ? "DETECTED" : "CLEAR"}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </section>

            <section className="soc-card">
              <div className="soc-card-header">
                <Activity size={18} />
                <h2>ML / Anomaly Signal</h2>
              </div>
              <div className="soc-card-body">
                <div className="data-row">
                  <span>ML Anomaly Detected</span>
                  <strong>{threatDetails.processing?.risk_assessment?.ml_anomaly ? "YES" : "NO"}</strong>
                </div>
                {mlResult && (
                  <>
                    <div className="data-row"><span>XGBoost</span><strong>{mlResult.detection?.prediction || "Unknown"}</strong></div>
                    <div className="data-row"><span>Isolation Forest</span><strong>{mlResult.anomaly?.is_anomaly ? "ANOMALY" : "NORMAL"}</strong></div>
                  </>
                )}
              </div>
            </section>
          </div>

          {/* MIDDLE: RAG & AI */}
          <div className="soc-grid-col">
            <section className="soc-card ai-accent-card">
              <div className="soc-card-header ai-header">
                <div style={{display: "flex", gap: "8px", alignItems: "center"}}>
                  <Sparkles size={18} />
                  <h2>AI Analysis</h2>
                </div>
                {aiContent.confidence_level && (
                  <span className={"ai-confidence "}>{aiContent.confidence_level}</span>
                )}
              </div>
              <div className="soc-card-body">
                <div className="ai-content-blocks">
                  <div className="ai-block">
                    <h4>Threat Explanation</h4>
                    <p>{aiContent.threat_explanation || "No explanation available."}</p>
                  </div>
                  <div className="ai-block">
                    <h4>Evidence & Risk</h4>
                    <p>{aiContent.evidence || "No evidence provided."}</p>
                    <p style={{marginTop: "8px"}}>{aiContent.risk_assessment || ""}</p>
                  </div>
                </div>
              </div>
            </section>

            <section className="soc-card">
              <div className="soc-card-header">
                <BookOpen size={18} />
                <h2>Retrieved Security Knowledge</h2>
              </div>
              <div className="soc-card-body">
                {retrievedDocs.length > 0 ? (
                  <div className="rag-documents">
                    {retrievedDocs.map((doc, i) => (
                      <div className="rag-doc" key={i}>
                        <FileText size={14} />
                        <div className="rag-doc-info">
                          <strong>{doc.filename}</strong>
                          <span>Similarity: {doc.score}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="empty-text">No RAG documents retrieved.</div>
                )}
              </div>
            </section>
          </div>

          {/* RIGHT: Q&A & MITIGATION */}
          <div className="soc-grid-col">
            <section className="soc-card">
              <div className="soc-card-header">
                <ShieldAlert size={18} />
                <h2>Recommended Action</h2>
              </div>
              <div className="soc-card-body">
                <div className="ai-content-blocks">
                  <div className="ai-block">
                    <h4>System Action</h4>
                    <p className="alert-domain" style={{display: "inline-block", marginTop: "4px"}}>{threatDetails.processing?.mitigation_action || "ALLOW"}</p>
                  </div>
                  <div className="ai-block">
                    <h4>AI Recommendation</h4>
                    <p>{aiContent.recommended_action || "No specific recommendation provided."}</p>
                  </div>
                </div>
              </div>
            </section>

            <section className="soc-card" style={{ flex: 1, display: "flex", flexDirection: "column" }}>
              <div className="soc-card-header">
                <Bot size={18} />
                <h2>Copilot Chat</h2>
              </div>
              <div className="soc-card-body" style={{ flex: 1, display: "flex", flexDirection: "column", padding: "16px" }}>
                <div className="reason-list" style={{ justifyContent: "flex-start", marginBottom: "16px" }}>
                  {SUGGESTED_QUESTIONS.map((q, i) => (
                    <button
                      key={i}
                      className="reason-badge"
                      onClick={() => handleSuggest(q)}
                      style={{ border: "none", cursor: "pointer" }}
                    >
                      {q}
                    </button>
                  ))}
                </div>

                <div className="small-thread" style={{ flex: 1, minHeight: "150px", maxHeight: "300px", marginBottom: "16px" }}>
                  {chatMessages.length === 0 ? (
                    <div className="empty-text">Ask a question to begin.</div>
                  ) : (
                    chatMessages.map((msg, i) => (
                      <div className="copilot-message" key={i} style={{marginBottom: "16px"}}>
                        <strong style={{display: "block", color: "#f1f5f9", fontSize: "13px", marginBottom: "4px"}}>{msg.q}</strong>
                        <p style={{margin: 0, color: "#cbd5e1", fontSize: "14px", lineHeight: 1.5, background: "#131a31", padding: "12px", borderRadius: "8px"}}>{msg.a}</p>
                      </div>
                    ))
                  )}
                </div>

                <form className="copilot-inline-form" onSubmit={handleAsk} style={{ marginTop: "auto" }}>
                  <input
                    type="text"
                    value={inputQuestion}
                    onChange={(e) => setInputQuestion(e.target.value)}
                    placeholder="Ask Gemini about this threat..."
                  />
                  <button type="submit"><Send size={16} /></button>
                </form>
              </div>
            </section>
          </div>
        </div>
      )}
    </main>
  );
}

export default AICopilotPage;
