from pathlib import Path
import sys
import json


# Get the rag directory
RAG_DIR = Path(__file__).resolve().parent.parent

if str(RAG_DIR) not in sys.path:
    sys.path.append(str(RAG_DIR))


from retrieval.retrieve import search
from llm.gemini_client import generate_analysis


def analyze_threat(threat_event):
    """
    Analyze a threat event using RAG + Gemini.

    Expected input:

    {
        "attack_type": "BOLA",
        "endpoint": "/api/users/456",
        "method": "GET",
        "source_ip": "192.168.1.10",
        "risk_score": 85,
        "severity": "HIGH"
    }
    """

    attack_type = threat_event.get("attack_type", "Unknown")
    endpoint = threat_event.get("endpoint", "Unknown")
    method = threat_event.get("method", "Unknown")
    source_ip = threat_event.get("source_ip", "Unknown")
    risk_score = threat_event.get("risk_score", 0)
    severity = threat_event.get("severity", "UNKNOWN")

    # ---------------------------------------------------------
    # STEP 1: Create a focused retrieval query
    # ---------------------------------------------------------
    #
    # We focus on the security behaviour rather than including
    # values such as source IP, risk score and severity.
    #

    threat_query = f"""
API security attack:

Attack Type: {attack_type}

Endpoint: {endpoint}

HTTP Method: {method}

Describe security indicators, suspicious behaviour,
detection patterns, and mitigation related to this attack.
"""

    # ---------------------------------------------------------
    # STEP 2: Retrieve relevant security knowledge
    # ---------------------------------------------------------

    retrieved_documents = search(
        threat_query,
        top_k=3
    )

    # ---------------------------------------------------------
    # STEP 3: Prepare retrieved knowledge for Gemini
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # STEP 4: Create Gemini prompt
    # ---------------------------------------------------------

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

## RETRIEVED SECURITY KNOWLEDGE

{knowledge_context}

## TASK

Return ONLY valid JSON.

The JSON must contain exactly these four fields:

{{
  "threat_explanation": "Explain why this event may represent the detected attack.",
  "evidence": "List the important indicators present in the event.",
  "risk_assessment": "Explain the significance of the risk score and severity.",
  "recommended_action": "Provide practical investigation and mitigation steps."
}}

IMPORTANT RULES:

- Use the retrieved knowledge as supporting context.
- Do not invent evidence.
- Do not add fields.
- Do not use Markdown.
- Do not wrap the JSON in code fences.
- Do not claim that an attack is confirmed unless the event provides
  enough evidence.
- Do not make the AI responsible for automatically blocking requests.
"""

    # ---------------------------------------------------------
    # STEP 5: Generate AI analysis
    # ---------------------------------------------------------

    ai_response = generate_analysis(prompt)

    # ---------------------------------------------------------
    # STEP 6: Convert Gemini JSON into Python dictionary
    # ---------------------------------------------------------

    try:
        structured_analysis = json.loads(ai_response)

    except json.JSONDecodeError:

        structured_analysis = {
            "threat_explanation": ai_response,
            "evidence": "",
            "risk_assessment": "",
            "recommended_action": ""
        }

    # ---------------------------------------------------------
    # STEP 7: Return final RAG result
    # ---------------------------------------------------------

    return {
        "attack_type": attack_type,
        "risk_score": risk_score,
        "severity": severity,

        "retrieved_documents": [
            {
                "filename": document["filename"],
                "score": round(document["score"], 4)
            }
            for document in retrieved_documents
        ],

        "ai_analysis": structured_analysis
    }


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    test_event = {
    "attack_type": "Resource Exhaustion",
    "endpoint": "/api/search",
    "method": "GET",
    "source_ip": "192.168.1.10",
    "risk_score": 90,
    "severity": "CRITICAL"
}

    result = analyze_threat(test_event)

    print("\n===== RAG THREAT ANALYSIS =====\n")

    print(f"Attack Type: {result['attack_type']}")
    print(f"Risk Score: {result['risk_score']}")
    print(f"Severity: {result['severity']}")

    print("\n===== RETRIEVED KNOWLEDGE =====\n")

    for document in result["retrieved_documents"]:

        print(
            f"{document['filename']} "
            f"(score: {document['score']})"
        )

    print("\n===== STRUCTURED AI ANALYSIS =====\n")

    print(
        json.dumps(
            result["ai_analysis"],
            indent=2,
            ensure_ascii=False
        )
    )