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
    # RAG QUERY
    # ============================================================

    threat_query = f"""
API security attack:

Attack Type: {attack_type}

Endpoint: {endpoint}

HTTP Method: {method}

Detector Evidence:
{evidence_text}

Describe security indicators, suspicious behaviour,
detection patterns, and mitigation related to this attack.
"""


    print(
        f"[RAG] Searching knowledge for {attack_type}..."
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
You are an AI cybersecurity analyst.

Analyze the following detected API security event.

## DETECTED THREAT

Attack Type: {attack_type}

Endpoint: {endpoint}

HTTP Method: {method}

Source IP: {source_ip}

Risk Score: {risk_score}/100

Severity: {severity}


## ACTUAL DETECTOR EVIDENCE

{evidence_text}


## RETRIEVED SECURITY KNOWLEDGE

{knowledge_context}


## TASK

Return ONLY valid JSON.

The JSON must contain exactly these four fields:

{{
  "threat_explanation": "Explain why this event may represent the detected attack using the actual detector evidence.",
  "evidence": "Explain the specific detector evidence present in this event.",
  "risk_assessment": "Explain the significance of the risk score and severity.",
  "recommended_action": "Provide practical investigation and mitigation steps."
}}


IMPORTANT RULES:

- Use the retrieved knowledge as supporting context.
- Give priority to the actual detector evidence.
- Do not invent evidence.
- Do not create evidence that is not present in the event.
- Do not change detector evidence codes.
- Do not add fields.
- Do not use Markdown.
- Do not wrap the JSON in code fences.
- Do not claim that an attack is confirmed unless the event provides enough evidence.
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
                "error": "AI analysis unavailable"
            }
        }


    # ============================================================
    # PARSE GEMINI RESPONSE
    # ============================================================

    try:

        structured_analysis = json.loads(
            ai_response
        )

    except json.JSONDecodeError:

        structured_analysis = {
            "threat_explanation": ai_response,
            "evidence": evidence_text,
            "risk_assessment": "",
            "recommended_action": ""
        }


    # ============================================================
    # RETURN RAG + GEMINI RESULT
    # ============================================================

    return {
        "attack_type": attack_type,

        "risk_score": risk_score,

        "severity": severity,

        "detector_evidence": detector_evidence,

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