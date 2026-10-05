from pathlib import Path
import sys
import json


RAG_DIR = Path(__file__).resolve().parent.parent

if str(RAG_DIR) not in sys.path:
    sys.path.append(str(RAG_DIR))


from retrieval.retrieve import search
from llm.gemini_client import generate_analysis


def analyze_threat(threat_event):
    """
    Analyze a detected API security threat using
    RAG-retrieved knowledge and Gemini.
    """

    attack_type = threat_event.get(
        "attack_type",
        "Unknown"
    )

    endpoint = threat_event.get(
        "endpoint",
        "Unknown"
    )

    method = threat_event.get(
        "method",
        "Unknown"
    )

    source_ip = threat_event.get(
        "source_ip",
        "Unknown"
    )

    risk_score = threat_event.get(
        "risk_score",
        0
    )

    severity = threat_event.get(
        "severity",
        "UNKNOWN"
    )

    detector_evidence = threat_event.get(
        "evidence",
        []
    )

    domain = threat_event.get(
        "domain",
        "API"
    )
    if domain not in {"API", "NETWORK", "ENDPOINT"}:
        domain = "API"

    detector_confidence = threat_event.get(
        "detector_confidence"
    )

    ml_prediction = threat_event.get(
        "ml_prediction"
    )

    ml_confidence = threat_event.get(
        "ml_confidence"
    )

    ml_anomaly = threat_event.get(
        "ml_anomaly",
        False
    )

    ml_anomaly_score = threat_event.get(
        "ml_anomaly_score"
    )


    # ============================================================
    # BUILD EVIDENCE TEXT
    # ============================================================

    evidence_text = ""

    if detector_evidence:

        evidence_lines = []

        for evidence in detector_evidence:

            code = evidence.get(
                "code",
                "UNKNOWN"
            )

            message = evidence.get(
                "message",
                ""
            )

            evidence_lines.append(
                f"- {code}: {message}"
            )

        evidence_text = "\n".join(
            evidence_lines
        )

    else:

        evidence_text = (
            "No specific detector evidence was provided."
        )


    # ============================================================
    # BUILD ML SIGNAL TEXT (SUPPORTING EVIDENCE ONLY)
    # ============================================================

    ml_parts = []
    if ml_prediction is not None:
        conf_str = f" (Confidence: {ml_confidence * 100:.1f}%)" if ml_confidence is not None else ""
        ml_parts.append(f"- XGBoost Prediction: {ml_prediction}{conf_str}")
    if ml_anomaly:
        score_str = f" (Anomaly Score: {ml_anomaly_score:.4f})" if ml_anomaly_score is not None else ""
        ml_parts.append(f"- Isolation Forest Anomaly: DETECTED{score_str}")
    elif ml_prediction is not None:
        ml_parts.append("- Isolation Forest Anomaly: NORMAL")

    if ml_parts:
        ml_signal_text = "\n".join(ml_parts)
    else:
        ml_signal_text = "No ML features or telemetry provided for this event."

    detector_confidence_text = (
        f"{detector_confidence * 100:.1f}%"
        if detector_confidence is not None
        else "N/A"
    )


    # ============================================================
    # RAG QUERY
    # ============================================================

    ml_query_hint = ""
    if ml_prediction and str(ml_prediction).upper() != "BENIGN":
        ml_query_hint = f"\nML Classification: {ml_prediction}"

    threat_query = f"""
Security attack in {domain} domain:

Attack Type: {attack_type}

Endpoint: {endpoint}

HTTP Method: {method}

Detector Evidence:
{evidence_text}{ml_query_hint}

Describe security indicators, suspicious behaviour,
detection patterns, and mitigation related to this attack.
"""


    print(
        f"[RAG] Searching knowledge for {attack_type} ({domain})..."
    )


    # ============================================================
    # RETRIEVE SECURITY KNOWLEDGE
    # ============================================================

    retrieved_documents = search(
        threat_query,
        top_k=3
    )


    knowledge_context = "\n\n".join(
        [
            f"""
SOURCE: {document['filename']}
SIMILARITY SCORE: {document['score']:.4f}

{document['text']}
"""
            for document in retrieved_documents
        ]
    )


    # ============================================================
    # GEMINI PROMPT
    # ============================================================

    prompt = f"""
You are an AI cybersecurity analyst evaluating an event flagged by our centralized intrusion detection system.

## DETECTED THREAT CONTEXT
- Attack Type: {attack_type}
- Security Domain: {domain}
- Endpoint: {endpoint}
- HTTP Method: {method}
- Source IP: {source_ip}
- Risk Score: {risk_score}/100
- Severity: {severity}
- Primary Detector Confidence: {detector_confidence_text}

## RULE-BASED DETECTOR EVIDENCE (AUTHORITATIVE)
{evidence_text}

## MACHINE LEARNING TELEMETRY (SUPPORTING EVIDENCE ONLY)
{ml_signal_text}

## RETRIEVED SECURITY KNOWLEDGE BASE (CONTEXTUAL REASONING)
{knowledge_context}

## TASK
Return ONLY valid JSON.
Do not use Markdown formatting or wrap the JSON in code fences.

The JSON object must contain exactly these five fields:
{{
  "threat_explanation": "Explain why this event may represent the detected attack using the actual detector evidence and context.",
  "evidence": "Explain the specific detector evidence present in this event, distinguishing between authoritative rule evidence and ML signals.",
  "risk_assessment": "Explain the significance of the risk score and severity.",
  "recommended_action": "Provide practical investigation and mitigation steps.",
  "confidence_level": "Must be one of: CONFIRMED, SUSPICIOUS, or UNKNOWN"
}}

## IMPORTANT RULES:
- Use the retrieved knowledge as supporting context for reasoning and mitigation.
- Treat rule-based detector evidence as authoritative detection evidence.
- Treat ML / anomaly output as supporting evidence only; do not treat ML output as proof by itself.
- Do not invent evidence or indicators that are not present in the event data.
- Do not change detector evidence codes.
- Do not claim that an attack is confirmed unless the event provides sufficient evidence.
- If the evidence provides clear, authoritative proof of the attack, set confidence_level to "CONFIRMED".
- If the evidence is ambiguous, partial, or primarily circumstantial/anomaly-based, set confidence_level to "SUSPICIOUS".
- If the evidence is insufficient, contradictory, or absent, set confidence_level to "UNKNOWN".
- The AI must explain the detection, not perform the detection itself.
- Do not make the AI responsible for automatically blocking requests.
"""


    # ============================================================
    # GEMINI ANALYSIS
    # ============================================================

    print(
        "[RAG] Sending retrieved context and detector evidence to Gemini..."
    )


    try:

        ai_response = generate_analysis(
            prompt
        )

    except Exception as exc:

        print(
            f"[RAG ERROR] Gemini analysis failed: {exc}"
        )

        return {
            "attack_type": attack_type,
            "risk_score": risk_score,
            "severity": severity,
            "domain": domain,
            "retrieved_documents": [
                {
                    "filename": document["filename"],
                    "score": round(
                        document["score"],
                        4
                    )
                }
                for document in retrieved_documents
            ],
            "ai_analysis": {
                "error": "AI analysis unavailable",
                "confidence_level": "UNKNOWN"
            }
        }


    # ============================================================
    # PARSE GEMINI RESPONSE
    # ============================================================

    try:

        structured_analysis = json.loads(
            ai_response
        )
        conf = str(structured_analysis.get("confidence_level", "")).upper()
        if conf not in {"CONFIRMED", "SUSPICIOUS", "UNKNOWN"}:
            structured_analysis["confidence_level"] = "CONFIRMED" if detector_evidence else "SUSPICIOUS"
        else:
            structured_analysis["confidence_level"] = conf

    except json.JSONDecodeError:

        cleaned_response = ai_response.strip()
        if cleaned_response.startswith("```"):
            parts = cleaned_response.split("```")
            if len(parts) >= 2:
                cleaned_response = parts[1]
                if cleaned_response.startswith("json"):
                    cleaned_response = cleaned_response[4:]
                cleaned_response = cleaned_response.strip()

        try:
            structured_analysis = json.loads(cleaned_response)
            conf = str(structured_analysis.get("confidence_level", "")).upper()
            if conf not in {"CONFIRMED", "SUSPICIOUS", "UNKNOWN"}:
                structured_analysis["confidence_level"] = "CONFIRMED" if detector_evidence else "SUSPICIOUS"
            else:
                structured_analysis["confidence_level"] = conf
        except Exception:
            structured_analysis = {
                "threat_explanation": ai_response,
                "evidence": evidence_text,
                "risk_assessment": "",
                "recommended_action": "",
                "confidence_level": "SUSPICIOUS"
            }


    # ============================================================
    # RETURN RAG + GEMINI RESULT
    # ============================================================

    return {
        "attack_type": attack_type,

        "risk_score": risk_score,

        "severity": severity,

        "detector_evidence": detector_evidence,

        "domain": domain,

        "retrieved_documents": [
            {
                "filename": document["filename"],
                "score": round(
                    document["score"],
                    4
                )
            }
            for document in retrieved_documents
        ],

        "ai_analysis": structured_analysis
    }


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":

    test_event = {

        "attack_type": "BOLA_IDOR",

        "endpoint": "/api/users/42",

        "method": "GET",

        "source_ip": "192.168.1.10",

        "risk_score": 92.8,

        "severity": "CRITICAL",

        "evidence": [
            {
                "code": "RESOURCE_OWNER_MISMATCH",
                "message": (
                    "Authenticated user user_17 "
                    "requested user 42 owned by user_42"
                )
            }
        ]
    }


    result = analyze_threat(
        test_event
    )


    print(
        "\n===== RAG + GEMINI RESULT =====\n"
    )

    print(
        json.dumps(
            result,
            indent=2
        )
    )