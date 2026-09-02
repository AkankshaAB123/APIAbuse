from pathlib import Path
import sys


# Allow Python to find the retrieval and llm modules
RAG_DIR = Path(__file__).resolve().parent.parent

if str(RAG_DIR) not in sys.path:
    sys.path.append(str(RAG_DIR))


from retrieval.retrieve import search
from llm.gemini_client import generate_analysis


def analyze_threat(
    attack_type,
    endpoint,
    method,
    source_ip,
    risk_score,
    severity
):
    """
    Retrieve relevant security knowledge and use Gemini
    to generate an AI-based threat assessment.
    """

    # Create a behaviour description for retrieval
    threat_query = f"""
Attack Type: {attack_type}
Endpoint: {endpoint}
HTTP Method: {method}
Source IP: {source_ip}
Risk Score: {risk_score}
Severity: {severity}

Analyze the security behaviour represented by this event.
"""

    # Retrieve relevant knowledge
    retrieved_documents = search(
        threat_query,
        top_k=3
    )

    # Combine retrieved knowledge
    knowledge_context = "\n\n".join(
        [
            f"""
SOURCE: {document['filename']}
SIMILARITY: {document['score']:.4f}

{document['text']}
"""
            for document in retrieved_documents
        ]
    )

    # Prompt Gemini using retrieved knowledge
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

Based only on the detected event and the retrieved security knowledge,
provide a concise security assessment.

Return the following sections:

### Threat Explanation
Explain why this activity may represent the detected attack.

### Evidence
Identify the important indicators from the event.

### Risk Assessment
Explain what the risk score and severity mean.

### Recommended Action
Provide practical mitigation or investigation steps.

Do not invent evidence that is not present in the detected event.
"""

    # Generate AI analysis
    ai_response = generate_analysis(prompt)

    return {
        "attack_type": attack_type,
        "risk_score": risk_score,
        "severity": severity,
        "retrieved_documents": [
            {
                "filename": document["filename"],
                "score": document["score"]
            }
            for document in retrieved_documents
        ],
        "ai_analysis": ai_response
    }


if __name__ == "__main__":

    # Sample threat event for testing
    result = analyze_threat(
        attack_type="BOLA",
        endpoint="/api/users/456",
        method="GET",
        source_ip="192.168.1.10",
        risk_score=85,
        severity="HIGH"
    )

    print("\n===== AI THREAT ANALYSIS =====\n")

    print(f"Attack Type: {result['attack_type']}")
    print(f"Risk Score: {result['risk_score']}")
    print(f"Severity: {result['severity']}")

    print("\n===== RETRIEVED DOCUMENTS =====\n")

    for document in result["retrieved_documents"]:
        print(
            f"{document['filename']} "
            f"(score: {document['score']:.4f})"
        )

    print("\n===== GEMINI ANALYSIS =====\n")
    print(result["ai_analysis"])