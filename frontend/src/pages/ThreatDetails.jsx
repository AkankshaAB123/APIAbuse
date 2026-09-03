import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { threats } from "../data/mockData";


function ThreatDetails() {

  const { id } = useParams();

  const [realThreat, setRealThreat] =
    useState(null);


  useEffect(() => {

    const storedThreat =
      localStorage.getItem("latestThreat");

    if (!storedThreat) {
      return;
    }

    try {

      const parsedThreat =
        JSON.parse(storedThreat);

      if (parsedThreat.event_id === id) {
        setRealThreat(parsedThreat);
      }

    } catch (error) {

      console.error(
        "Failed to read stored threat:",
        error
      );

    }

  }, [id]);


  /* =====================================================
     REAL BACKEND THREAT
  ===================================================== */

  if (realThreat) {

    const risk =
      realThreat.risk_assessment;

    const ai =
      realThreat.ai_analysis;

    const aiContent =
      ai?.ai_analysis;

    const retrievedDocuments =
      ai?.retrieved_documents || [];

    const aiError =
      ai?.error;


    return (
      <div className="details-page">

        {/* =================================================
            HEADER
        ================================================= */}

        <div className="details-header">

          <div>

            <Link
              to="/attack-simulation"
              className="back-link"
            >
              ← Back to Simulation
            </Link>

            <h1>
              Threat Details
            </h1>

            <p>
              Detailed security analysis of the
              detected API event.
            </p>

          </div>

          <span className="threat-id">
            {realThreat.event_id}
          </span>

        </div>


        {/* =================================================
            THREAT SUMMARY
        ================================================= */}

        <div className="details-grid">

          <div className="detail-card">

            <span className="detail-label">
              Attack Type
            </span>

            <strong className="detail-value">
              {risk?.attack_types?.join(", ") ||
                ai?.attack_type ||
                "Unknown"}
            </strong>

          </div>


          <div className="detail-card">

            <span className="detail-label">
              Source IP
            </span>

            <strong className="detail-value">
              {realThreat.source_ip ||
                "Unknown"}
            </strong>

          </div>


          <div className="detail-card">

            <span className="detail-label">
              Risk Score
            </span>

            <strong className="detail-value risk-value">
              {risk?.risk_score ?? 0}/100
            </strong>

          </div>


          <div className="detail-card">

            <span className="detail-label">
              Risk Level
            </span>

            <strong className="detail-value">
              {risk?.risk_level ||
                ai?.severity ||
                "UNKNOWN"}
            </strong>

          </div>


          <div className="detail-card">

            <span className="detail-label">
              Action Taken
            </span>

            <strong className="detail-value">
              {realThreat.mitigation_action ||
                "ALLOW"}
            </strong>

          </div>


          <div className="detail-card">

            <span className="detail-label">
              Detection Status
            </span>

            <strong className="detail-value">
              {risk?.threat_detected
                ? "DETECTED"
                : "SAFE"}
            </strong>

          </div>

        </div>


        {/* =================================================
            DETECTION INFORMATION
        ================================================= */}

        <div className="information-card">

          <h2>
            Detection Information
          </h2>


          <div className="information-row">

            <span>
              Detection Source
            </span>

            <strong>
              API Abuse Detection Engine
            </strong>

          </div>


          <div className="information-row">

            <span>
              Detector Results
            </span>

            <strong>
              {realThreat.detector_results?.length ||
                0}
            </strong>

          </div>


          <div className="information-row">

            <span>
              Threat Status
            </span>

            <strong>
              {risk?.threat_detected
                ? "Threat Detected"
                : "No Threat"}
            </strong>

          </div>


          <div className="information-row">

            <span>
              Risk Level
            </span>

            <strong>
              {risk?.risk_level || "UNKNOWN"}
            </strong>

          </div>


          <div className="information-row">

            <span>
              Detection Evidence
            </span>

            <strong>
              {risk?.reasons?.length || 0}
              {" "}
              indicator(s)
            </strong>

          </div>


          {/* =================================================
              EVIDENCE LIST
          ================================================= */}

          {risk?.reasons?.length > 0 && (

            <div className="ai-evidence-list">

              {risk.reasons.map(
                (reason, index) => (

                  <div
                    key={index}
                    className="evidence-item"
                  >
                    • {reason}
                  </div>

                )
              )}

            </div>

          )}

        </div>


        {/* =================================================
            AI / RAG ANALYSIS
        ================================================= */}

        <div className="information-card ai-analysis-card">

          <div className="ai-analysis-header">

            <div>

              <h2>
                AI Analysis
              </h2>

              <p>
                RAG + Gemini Security Intelligence
              </p>

            </div>

            <span className="ai-badge">
              AI POWERED
            </span>

          </div>


          {/* =================================================
              GEMINI SUCCESS
          ================================================= */}

          {aiContent ? (

            <>

              <div className="ai-status-success">

                <span className="ai-status-dot"></span>

                Gemini analysis generated successfully

              </div>


              {/* Threat Explanation */}

              <div className="ai-section">

                <h3>
                  Threat Explanation
                </h3>

                <p>
                  {aiContent.threat_explanation ||
                    "No explanation provided."}
                </p>

              </div>


              {/* Evidence */}

              <div className="ai-section">

                <h3>
                  Evidence
                </h3>

                <p>
                  {aiContent.evidence ||
                    "No additional evidence provided."}
                </p>

              </div>


              {/* Risk Assessment */}

              <div className="ai-section">

                <h3>
                  Risk Assessment
                </h3>

                <p>
                  {aiContent.risk_assessment ||
                    "No additional risk assessment provided."}
                </p>

              </div>


              {/* Recommended Action */}

              <div className="ai-section">

                <h3>
                  Recommended Action
                </h3>

                <p>
                  {aiContent.recommended_action ||
                    "No recommendation provided."}
                </p>

              </div>


              {/* =================================================
                  RETRIEVED KNOWLEDGE
              ================================================= */}

              {retrievedDocuments.length > 0 && (

                <div className="ai-section">

                  <h3>
                    Retrieved Security Knowledge
                  </h3>

                  <p className="ai-section-description">
                    Security knowledge retrieved by
                    the RAG pipeline and supplied as
                    context for the AI analysis.
                  </p>


                  <div className="retrieved-documents">

                    {retrievedDocuments.map(
                      (document, index) => (

                        <div
                          key={`${document.filename}-${index}`}
                          className="retrieved-document"
                        >

                          <span>
                            {document.filename}
                          </span>

                          <span>
                            Similarity:{" "}
                            {document.score}
                          </span>

                        </div>

                      )
                    )}

                  </div>

                </div>

              )}

            </>

          ) : (

            /* =================================================
               GEMINI UNAVAILABLE
            ================================================= */

            <>

              <div className="ai-status-warning">

                <span className="ai-status-dot"></span>

                Gemini analysis temporarily unavailable

              </div>


              <div className="ai-fallback-message">

                <h3>
                  AI Analysis Status
                </h3>

                <p>

                  {aiError
                    ? "The threat was successfully detected and processed, but the Gemini AI analysis could not be generated because the AI service rate limit was reached."
                    : "The threat was successfully detected and processed, but an AI-generated analysis is not currently available."
                  }

                </p>

                <p>

                  The detection engine, risk scoring,
                  mitigation decision, and security
                  event processing completed successfully.

                </p>

              </div>


              {/* Show retrieved documents if available */}

              {retrievedDocuments.length > 0 && (

                <div className="ai-section">

                  <h3>
                    Retrieved Security Knowledge
                  </h3>

                  <p className="ai-section-description">
                    The RAG retrieval component successfully
                    identified relevant security knowledge.
                  </p>

                  <div className="retrieved-documents">

                    {retrievedDocuments.map(
                      (document, index) => (

                        <div
                          key={`${document.filename}-${index}`}
                          className="retrieved-document"
                        >

                          <span>
                            {document.filename}
                          </span>

                          <span>
                            Similarity:{" "}
                            {document.score}
                          </span>

                        </div>

                      )
                    )}

                  </div>

                </div>

              )}

            </>

          )}

        </div>


        {/* =================================================
            MITIGATION
        ================================================= */}

        <div className="information-card">

          <h2>
            Mitigation
          </h2>

          <p>
            Recommended system action:
            <strong>
              {" "}
              {realThreat.mitigation_action ||
                "ALLOW"}
            </strong>
          </p>

          <p>
            The mitigation decision is based on
            the calculated risk level produced by
            the risk assessment engine.
          </p>

          <div className="information-row">

            <span>
              Risk-Based Decision
            </span>

            <strong>
              {risk?.risk_level || "UNKNOWN"}
            </strong>

          </div>

          <div className="information-row">

            <span>
              System Response
            </span>

            <strong>
              {realThreat.mitigation_action ||
                "ALLOW"}
            </strong>

          </div>

        </div>

      </div>
    );
  }


  /* =====================================================
     FALLBACK — EXISTING MOCK THREATS
  ===================================================== */

  const threat = threats.find(
    (item) => item.id === id
  );


  if (!threat) {

    return (
      <div className="details-page">

        <h1>
          Threat Not Found
        </h1>

        <Link to="/">
          ← Back to Dashboard
        </Link>

      </div>
    );

  }


  /* =====================================================
     MOCK THREAT DETAILS
  ===================================================== */

  return (
    <div className="details-page">

      <div className="details-header">

        <div>

          <Link
            to="/"
            className="back-link"
          >
            ← Back to Dashboard
          </Link>

          <h1>
            Threat Details
          </h1>

          <p>
            Detailed security information for
            this threat event.
          </p>

        </div>

        <span className="threat-id">
          {threat.id}
        </span>

      </div>


      <div className="details-grid">

        <div className="detail-card">

          <span className="detail-label">
            Attack Type
          </span>

          <strong className="detail-value">
            {threat.attackType}
          </strong>

        </div>


        <div className="detail-card">

          <span className="detail-label">
            Source IP
          </span>

          <strong className="detail-value">
            {threat.sourceIp}
          </strong>

        </div>


        <div className="detail-card">

          <span className="detail-label">
            Risk Score
          </span>

          <strong className="detail-value risk-value">
            {threat.riskScore}/100
          </strong>

        </div>


        <div className="detail-card">

          <span className="detail-label">
            Severity
          </span>

          <strong className="detail-value">
            {threat.severity}
          </strong>

        </div>


        <div className="detail-card">

          <span className="detail-label">
            Action Taken
          </span>

          <strong className="detail-value">
            {threat.action}
          </strong>

        </div>


        <div className="detail-card">

          <span className="detail-label">
            Detection Time
          </span>

          <strong className="detail-value">
            {threat.timestamp}
          </strong>

        </div>

      </div>


      <div className="information-card">

        <h2>
          Detection Information
        </h2>

        <div className="information-row">

          <span>
            Detection Source
          </span>

          <strong>
            AI Threat Detection
          </strong>

        </div>

        <div className="information-row">

          <span>
            Confidence
          </span>

          <strong>
            {Math.round(
              threat.riskScore * 0.98
            )}%
          </strong>

        </div>

        <div className="information-row">

          <span>
            Status
          </span>

          <strong>
            Detected
          </strong>

        </div>

      </div>


      <div className="information-card">

        <h2>
          AI Analysis
        </h2>

        <p className="placeholder-text">
          Run a real attack simulation to
          generate RAG + Gemini analysis.
        </p>

      </div>


      <div className="information-card">

        <h2>
          Mitigation
        </h2>

        <p>
          Recommended action:
          <strong>
            {" "}
            {threat.action}
          </strong>
        </p>

      </div>

    </div>
  );
}


export default ThreatDetails;