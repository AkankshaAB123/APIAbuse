import { useState } from "react";
import { Link } from "react-router-dom";

import {
  ArrowLeft,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Lock,
  Brain,
  Loader2,
  FileText,
  Target,
  Activity
} from "lucide-react";

import { checkAPISecurity } from "../services/api";


function APISecurityCheck() {

  const [formData, setFormData] = useState({
    endpoint: "",
    method: "GET",
    authentication: "authenticated",
    sensitive: "no"
  });

  const [result, setResult] = useState(null);

  const [loading, setLoading] = useState(false);

  const [error, setError] = useState("");


  /* =========================================================
     HANDLE INPUT CHANGES
  ========================================================= */

  const handleChange = (event) => {

    const {
      name,
      value
    } = event.target;

    setFormData((previous) => ({
      ...previous,
      [name]: value
    }));

  };


  /* =========================================================
     RESET FORM
  ========================================================= */

  const resetForm = () => {

    setFormData({
      endpoint: "",
      method: "GET",
      authentication: "authenticated",
      sensitive: "no"
    });

    setResult(null);

    setError("");

  };


  /* =========================================================
     SUBMIT SECURITY CHECK
  ========================================================= */

  const handleSubmit = async (event) => {

    event.preventDefault();

    setError("");

    setResult(null);


    /* ---------------------------------------------------------
       BASIC VALIDATION
    --------------------------------------------------------- */

    if (!formData.endpoint.trim()) {

      setError(
        "Please enter the API URL or endpoint you want to assess."
      );

      return;

    }


    try {

      setLoading(true);


      /*
       * For this first version, we only collect
       * information that a normal API owner can
       * easily understand.
       *
       * The backend will be updated separately
       * to perform the appropriate assessment.
       */

      const payload = {

        endpoint:
          formData.endpoint.trim(),

        method:
          formData.method,

        source_ip:
          "127.0.0.1",

        user_id:
          null,

        session_id:
          null,

        is_authenticated:
          formData.authentication ===
          "authenticated",

        resource_id:
          null,

        owner_id:
          null,

        is_sensitive:
          formData.sensitive === "yes",

        query_params: {},

        path_params: {},

        headers: {},

        body: null

      };


      const data =
        await checkAPISecurity(
          payload
        );


      console.log(
        "API Security Assessment:",
        data
      );


      setResult(data);

    } catch (err) {

      console.error(
        "API security assessment failed:",
        err
      );

      setError(
        err.message ||
        "Unable to complete the API security assessment."
      );

    } finally {

      setLoading(false);

    }

  };


  /* =========================================================
     SCORE CLASS
  ========================================================= */

  const getScoreClass = (score) => {

    if (score >= 90) {
      return "critical";
    }

    if (score >= 70) {
      return "high";
    }

    if (score >= 40) {
      return "medium";
    }

    return "low";

  };


  const score =
    Number(
      result?.security_score || 0
    );


  const scoreClass =
    getScoreClass(score);


  /* =========================================================
     AI RESPONSE
  ========================================================= */

  const aiData =
    result?.ai_analysis || null;


  const nestedAI =
    aiData?.ai_analysis || aiData;


  const threatExplanation =
    nestedAI?.threat_explanation ||
    aiData?.threat_explanation ||
    null;


  const aiRiskAssessment =
    nestedAI?.risk_assessment ||
    aiData?.risk_assessment ||
    null;


  const recommendedAction =
    nestedAI?.recommended_action ||
    aiData?.recommended_action ||
    null;


  const aiEvidence =
    nestedAI?.evidence ||
    aiData?.evidence ||
    [];


  const detectorEvidence =
    aiData?.detector_evidence ||
    [];


  const retrievedDocuments =
    aiData?.retrieved_documents ||
    aiData?.retrieved_docs ||
    [];


  const displayValue = (value) => {

    if (
      value === null ||
      value === undefined
    ) {

      return "";

    }


    if (
      typeof value === "string"
    ) {

      return value;

    }


    return JSON.stringify(
      value,
      null,
      2
    );

  };


  return (

    <main className="page-content">


      {/* =====================================================
          PAGE HEADER
      ===================================================== */}

      <div className="page-header">

        <div>

          <Link
            to="/enterprise"
            className="back-link"
          >

            <ArrowLeft size={16} />

            Enterprise

          </Link>


          <h1>
            API Security Check
          </h1>


          <p>
            Assess the security of your API using our threat detection system.
          </p>

        </div>

      </div>


      {/* =====================================================
          MAIN CONTENT
      ===================================================== */}

      <div
        style={{
          display: "grid",
          gridTemplateColumns:
            "minmax(0, 1fr) minmax(0, 0.9fr)",
          gap: "24px",
          alignItems: "start"
        }}
      >


        {/* ===================================================
            SIMPLE INPUT FORM
        =================================================== */}

        <div className="analytics-info-card">


          <div
            className="analytics-chart-header"
            style={{
              marginBottom: "28px"
            }}
          >

            <div>

              <h2>
                Check Your API
              </h2>

              <p>
                Provide a few basic details about your API.
              </p>

            </div>

            <ShieldCheck size={26} />

          </div>


          <form
            onSubmit={handleSubmit}
          >


            {/* =================================================
                API URL
            ================================================= */}

            <div className="form-group">

              <label>
                API URL / Endpoint
              </label>

              <input
                type="text"
                name="endpoint"
                value={
                  formData.endpoint
                }
                onChange={
                  handleChange
                }
                placeholder="https://your-api.com/api/users/123"
              />

              <small>
                Enter the API URL or endpoint you want to assess.
              </small>

            </div>


            {/* =================================================
                HTTP METHOD
            ================================================= */}

            <div className="form-group">

              <label>
                HTTP Method
              </label>

              <select
                name="method"
                value={
                  formData.method
                }
                onChange={
                  handleChange
                }
              >

                <option value="GET">
                  GET — Read data
                </option>

                <option value="POST">
                  POST — Create data
                </option>

                <option value="PUT">
                  PUT — Replace data
                </option>

                <option value="PATCH">
                  PATCH — Update data
                </option>

                <option value="DELETE">
                  DELETE — Delete data
                </option>

              </select>

            </div>


            {/* =================================================
                AUTHENTICATION
            ================================================= */}

            <div className="form-group">

              <label>
                Authentication
              </label>

              <select
                name="authentication"
                value={
                  formData.authentication
                }
                onChange={
                  handleChange
                }
              >

                <option value="authenticated">
                  Authentication is required
                </option>

                <option value="unauthenticated">
                  No authentication is required
                </option>

              </select>

              <small>
                Tell us whether users need to be authenticated to use this API.
              </small>

            </div>


            {/* =================================================
                SENSITIVE DATA
            ================================================= */}

            <div className="form-group">

              <label>
                Does this API handle sensitive data?
              </label>

              <select
                name="sensitive"
                value={
                  formData.sensitive
                }
                onChange={
                  handleChange
                }
              >

                <option value="no">
                  No
                </option>

                <option value="yes">
                  Yes
                </option>

              </select>

              <small>
                Examples include personal, financial, medical or private information.
              </small>

            </div>


            {/* =================================================
                INFORMATION BOX
            ================================================= */}

            <div
              style={{
                padding: "16px",
                marginBottom: "22px",
                borderRadius: "10px",
                background:
                  "rgba(139,92,246,0.08)",
                border:
                  "1px solid rgba(139,92,246,0.2)"
              }}
            >

              <div
                style={{
                  display: "flex",
                  gap: "10px",
                  alignItems: "flex-start"
                }}
              >

                <ShieldCheck
                  size={20}
                />

                <div>

                  <strong>
                    How this works
                  </strong>

                  <p
                    style={{
                      marginTop: "6px",
                      marginBottom: 0
                    }}
                  >
                    The system analyzes the information
                    you provide and generates a security
                    assessment with detected risks,
                    recommendations and AI-powered analysis.
                  </p>

                </div>

              </div>

            </div>


            {/* =================================================
                ERROR
            ================================================= */}

            {error && (

              <div
                style={{
                  padding: "14px",
                  marginBottom: "18px",
                  borderRadius: "10px",
                  background:
                    "rgba(239,68,68,0.1)",
                  border:
                    "1px solid rgba(239,68,68,0.35)",
                  color: "#fca5a5"
                }}
              >

                <strong>
                  Unable to assess API
                </strong>

                <br />

                {error}

              </div>

            )}


            {/* =================================================
                BUTTONS
            ================================================= */}

            <div
              style={{
                display: "flex",
                gap: "12px"
              }}
            >

              <button
                type="submit"
                className="view-threat-button"
                disabled={loading}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: "8px",
                  flex: 1
                }}
              >

                {loading ? (

                  <>

                    <Loader2
                      size={16}
                      className="spin"
                    />

                    ANALYZING...

                  </>

                ) : (

                  <>

                    <ShieldCheck
                      size={16}
                    />

                    CHECK API SECURITY

                  </>

                )}

              </button>


              <button
                type="button"
                className="view-threat-button"
                onClick={
                  resetForm
                }
                disabled={loading}
              >

                RESET

              </button>

            </div>

          </form>

        </div>


        {/* ===================================================
            RESULT PANEL
        =================================================== */}

        <div>


          {/* =================================================
              INITIAL STATE
          ================================================= */}

          {!result &&
          !loading && (

            <div className="analytics-info-card">

              <div
                style={{
                  textAlign: "center",
                  padding: "55px 25px"
                }}
              >

                <ShieldCheck
                  size={58}
                  style={{
                    marginBottom: "18px"
                  }}
                />


                <h2>
                  Ready to Check
                </h2>


                <p>
                  Enter your API details and we'll
                  analyze the request for security risks.
                </p>

              </div>

            </div>

          )}


          {/* =================================================
              LOADING
          ================================================= */}

          {loading && (

            <div className="analytics-info-card">

              <div
                style={{
                  textAlign: "center",
                  padding: "65px 25px"
                }}
              >

                <Loader2
                  size={48}
                  className="spin"
                />


                <h2>
                  Analyzing API Security
                </h2>


                <p>
                  Running security detection and risk analysis...
                </p>

              </div>

            </div>

          )}


          {/* =================================================
              RESULTS
          ================================================= */}

          {result &&
          !loading && (

            <div>


              {/* =================================================
                  SECURITY SCORE
              ================================================= */}

              <div
                className="analytics-info-card"
                style={{
                  marginBottom: "18px"
                }}
              >

                <div
                  style={{
                    textAlign: "center"
                  }}
                >

                  <div
                    style={{
                      fontSize: "13px",
                      opacity: 0.7
                    }}
                  >

                    API SECURITY SCORE

                  </div>


                  <div
                    className={
                      `security-score ${scoreClass}`
                    }
                  >

                    {score.toFixed(1)}

                  </div>


                  <div
                    className={
                      `risk-badge ${scoreClass}`
                    }
                  >

                    {result.risk_level}

                  </div>

                </div>

              </div>


              {/* =================================================
                  SECURITY STATUS
              ================================================= */}

              <div
                className="analytics-info-card"
                style={{
                  marginBottom: "18px"
                }}
              >

                <div className="summary-item">

                  {result.threat_detected ? (

                    <ShieldAlert
                      size={25}
                    />

                  ) : (

                    <CheckCircle
                      size={25}
                    />

                  )}


                  <div>

                    <strong>

                      {result.threat_detected

                        ? "Security Threat Detected"

                        : "No Security Threat Detected"}

                    </strong>


                    <p>

                      {result.threat_detected

                        ? "The security analysis identified a potential threat."

                        : "No security threat was detected from the available information."}

                    </p>

                  </div>

                </div>


                <div className="summary-item">

                  <Lock size={20} />

                  <div>

                    <strong>
                      Recommended Action
                    </strong>

                    <p>
                      {result.mitigation_action ||
                        "ALLOW"}
                    </p>

                  </div>

                </div>

              </div>


              {/* =================================================
                  ATTACK TYPES
              ================================================= */}

              {Array.isArray(
                result.attack_types
              ) &&
              result.attack_types.length > 0 && (

                <div
                  className="analytics-info-card"
                  style={{
                    marginBottom: "18px"
                  }}
                >

                  <h2>
                    Security Findings
                  </h2>


                  {result.attack_types.map(
                    (type) => (

                      <div
                        key={type}
                        className="risk-row"
                      >

                        <span>

                          <AlertTriangle
                            size={16}
                          />

                          {type}

                        </span>


                        <strong>
                          DETECTED
                        </strong>

                      </div>

                    )
                  )}

                </div>

              )}


              {/* =================================================
                  DETECTION REASONS
              ================================================= */}

              {Array.isArray(
                result.reasons
              ) &&
              result.reasons.length > 0 && (

                <div
                  className="analytics-info-card"
                  style={{
                    marginBottom: "18px"
                  }}
                >

                  <h2>
                    Why was this detected?
                  </h2>


                  {result.reasons.map(
                    (
                      reason,
                      index
                    ) => (

                      <div
                        key={index}
                        className="summary-item"
                      >

                        <XCircle
                          size={18}
                        />

                        <div>

                          <p>
                            {reason}
                          </p>

                        </div>

                      </div>

                    )
                  )}

                </div>

              )}


              {/* =================================================
                  AI ANALYSIS
              ================================================= */}

              {aiData && (

                <div
                  className="analytics-info-card"
                  style={{
                    marginBottom: "18px"
                  }}
                >

                  <div
                    className="analytics-chart-header"
                  >

                    <div>

                      <h2>
                        AI Security Analysis
                      </h2>

                      <p>
                        RAG + Gemini security analysis
                      </p>

                    </div>

                    <Brain
                      size={24}
                    />

                  </div>


                  {/* ATTACK TYPE */}

                  {aiData.attack_type && (

                    <div
                      className="summary-item"
                      style={{
                        marginTop: "22px"
                      }}
                    >

                      <Target
                        size={20}
                      />

                      <div>

                        <strong>
                          Attack Type
                        </strong>

                        <p>
                          {aiData.attack_type}
                        </p>

                      </div>

                    </div>

                  )}


                  {/* AI SCORE */}

                  {aiData.risk_score !==
                    undefined && (

                    <div
                      className="summary-item"
                    >

                      <Activity
                        size={20}
                      />

                      <div>

                        <strong>
                          AI Risk Score
                        </strong>

                        <p>
                          {aiData.risk_score}
                        </p>

                      </div>

                    </div>

                  )}


                  {/* SEVERITY */}

                  {aiData.severity && (

                    <div
                      className="summary-item"
                    >

                      <AlertTriangle
                        size={20}
                      />

                      <div>

                        <strong>
                          Severity
                        </strong>

                        <p>
                          {aiData.severity}
                        </p>

                      </div>

                    </div>

                  )}


                  {/* THREAT EXPLANATION */}

                  {threatExplanation && (

                    <div
                      style={{
                        marginTop: "22px",
                        paddingTop: "20px",
                        borderTop:
                          "1px solid #303858"
                      }}
                    >

                      <h3>
                        Threat Explanation
                      </h3>


                      <p>

                        {typeof threatExplanation ===
                        "string"

                          ? threatExplanation

                          : threatExplanation.summary ||
                            threatExplanation.explanation ||
                            displayValue(
                              threatExplanation
                            )}

                      </p>

                    </div>

                  )}


                  {/* RISK ASSESSMENT */}

                  {aiRiskAssessment && (

                    <div
                      style={{
                        marginTop: "22px"
                      }}
                    >

                      <h3>
                        Risk Assessment
                      </h3>


                      <div
                        style={{
                          padding: "15px",
                          borderRadius: "10px",
                          background:
                            "rgba(99,102,241,0.08)",
                          border:
                            "1px solid rgba(99,102,241,0.2)",
                          whiteSpace: "pre-wrap"
                        }}
                      >

                        {displayValue(
                          aiRiskAssessment
                        )}

                      </div>

                    </div>

                  )}


                  {/* AI EVIDENCE */}

                  {Array.isArray(
                    aiEvidence
                  ) &&
                  aiEvidence.length > 0 && (

                    <div
                      style={{
                        marginTop: "22px"
                      }}
                    >

                      <h3>
                        AI Evidence
                      </h3>


                      {aiEvidence.map(
                        (
                          evidence,
                          index
                        ) => (

                          <div
                            key={index}
                            className="summary-item"
                          >

                            <CheckCircle
                              size={18}
                            />

                            <div>

                              <p>

                                {typeof evidence ===
                                "string"

                                  ? evidence

                                  : evidence.message ||
                                    evidence.description ||
                                    displayValue(
                                      evidence
                                    )}

                              </p>

                            </div>

                          </div>

                        )
                      )}

                    </div>

                  )}


                  {/* DETECTOR EVIDENCE */}

                  {Array.isArray(
                    detectorEvidence
                  ) &&
                  detectorEvidence.length > 0 && (

                    <div
                      style={{
                        marginTop: "22px"
                      }}
                    >

                      <h3>
                        Detector Evidence
                      </h3>


                      {detectorEvidence.map(
                        (
                          evidence,
                          index
                        ) => (

                          <div
                            key={index}
                            className="summary-item"
                          >

                            <ShieldAlert
                              size={18}
                            />

                            <div>

                              <strong>

                                {evidence.code ||
                                  "Security Evidence"}

                              </strong>


                              <p>

                                {evidence.message ||
                                  displayValue(
                                    evidence
                                  )}

                              </p>

                            </div>

                          </div>

                        )
                      )}

                    </div>

                  )}


                  {/* RECOMMENDATION */}

                  {recommendedAction && (

                    <div
                      style={{
                        marginTop: "22px"
                      }}
                    >

                      <h3>
                        Recommended Action
                      </h3>


                      <div
                        style={{
                          padding: "16px",
                          borderRadius: "10px",
                          background:
                            "rgba(34,197,94,0.08)",
                          border:
                            "1px solid rgba(34,197,94,0.2)",
                          whiteSpace: "pre-wrap"
                        }}
                      >

                        {typeof recommendedAction ===
                        "string"

                          ? recommendedAction

                          : displayValue(
                              recommendedAction
                            )}

                      </div>

                    </div>

                  )}


                  {/* RAG DOCUMENTS */}

                  {Array.isArray(
                    retrievedDocuments
                  ) &&
                  retrievedDocuments.length > 0 && (

                    <div
                      style={{
                        marginTop: "24px"
                      }}
                    >

                      <h3>
                        Knowledge Used by RAG
                      </h3>


                      {retrievedDocuments.map(
                        (
                          document,
                          index
                        ) => {

                          const documentName =
                            document.document ||
                            document.filename ||
                            document.name ||
                            document.source ||
                            `Knowledge Document ${index + 1}`;


                          const documentScore =
                            document.score;


                          return (

                            <div
                              key={index}
                              className="summary-item"
                            >

                              <FileText
                                size={19}
                              />

                              <div>

                                <strong>
                                  {documentName}
                                </strong>


                                {documentScore !==
                                  undefined && (

                                  <p>
                                    Similarity score:{" "}
                                    {Number(
                                      documentScore
                                    ).toFixed(4)}
                                  </p>

                                )}

                              </div>

                            </div>

                          );

                        }

                      )}

                    </div>

                  )}

                </div>

              )}


              {/* CHECK ID */}

              <div
                style={{
                  fontSize: "11px",
                  opacity: 0.5,
                  wordBreak: "break-all",
                  marginBottom: "20px"
                }}
              >

                Check ID:{" "}
                {result.event_id}

              </div>

            </div>

          )}

        </div>

      </div>

    </main>

  );

}


export default APISecurityCheck;