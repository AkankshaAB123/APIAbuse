import pytest
from fastapi.testclient import TestClient
import sys
from pathlib import Path

# Ensure backend module is in path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.main import app

client = TestClient(app)

def test_xss_workshop_demo():
    """
    Automates the manual verification of the XSS workshop demonstration.
    """
    payload = "<script>alert('XSS')</script>"
    
    # 1. Hit the custom XSS demo endpoint
    response = client.get(f"/workshop/xss-demo?q={payload}")
    
    # 2. Verify response format and sandbox rendering
    assert response.status_code == 200
    data = response.json()
    
    assert "html" in data
    assert "result" in data
    assert payload in data["html"], "The sandbox must render the attacker payload."
    
    # 3. Verify backend independently detected XSS
    processing_result = data["result"]
    assert processing_result["status"] == "PROCESSED"
    
    detector_results = processing_result.get("detector_results", [])
    xss_detected = False
    evidence_found = False
    
    for res in detector_results:
        if res.get("detected") and res.get("attack_type") == "XSS":
            xss_detected = True
            # Verify evidence was extracted
            if res.get("evidence"):
                evidence_found = True
            break
            
    assert xss_detected, "The IDS engine failed to independently detect the XSS payload from the raw request."
    assert evidence_found, "The IDS engine detected XSS but failed to extract the payload as evidence."
    
    # 4. Verify risk assessment appropriately flagged it
    risk = processing_result.get("risk_assessment")
    assert risk is not None
    assert risk.get("risk_level") in ["HIGH", "CRITICAL"], "The risk engine should flag XSS as HIGH or CRITICAL risk."
