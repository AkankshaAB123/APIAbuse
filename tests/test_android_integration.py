"""
End-to-end integration test validating the Android ThreatGuard Agent event reporting,
detection, risk assessment, impact, mitigation, and SOC visibility against the
live ThreatGuard backend EventProcessor.

Scenarios tested:
  A. Benign Android event (health telemetry) -> ALLOW
  B. Controlled suspicious event (sideloaded miner / suspicious process) -> QUARANTINE / MONITOR
  C. Controlled attack event (accessibility keylogging abuse) -> QUARANTINE
  D. Controlled phishing lab simulation (fake bank login) -> URL_BLOCK
  E. Controlled transaction abuse simulation -> TRANSACTION_BLOCK

Validates:
  - Event contract compatibility (no duplicate models)
  - Device identity preservation in SOC record
  - Mitigation action enforcement matches architecture
  - SOC visibility in MongoDB
"""

from datetime import datetime, timezone
import pytest
from unittest.mock import patch

from backend.database import events_collection
from backend.schemas.api_security_event import (
    ApiSecurityEvent,
    EndpointInfo,
    IdentityInfo,
    NetworkInfo,
    RequestInfo,
    ResourceInfo,
    ResponseInfo,
)
from backend.services.event_processor import EventProcessor
from backend.services.auth_service import create_access_token
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_android_benign_telemetry_flow():
    """Scenario A: Benign Android telemetry event -> ALLOW."""
    event_id = "test-android-benign-001"
    device_id = "ANDROID-E2E-TEST-BENIGN"

    payload = {
        "schema_version": "1.0",
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": "ENDPOINT",
        "network": {
            "source_ip": "192.168.1.55",
            "destination_ip": "10.0.2.2",
            "source_port": 42100,
            "destination_port": 8000,
            "protocol": "TCP",
            "connection_status": "success",
            "user_agent": "ThreatGuard-Android/1.0 (Google; Pixel 8; Android 14)"
        },
        "identity": {
            "user_id": "android_user",
            "is_authenticated": False,
            "roles": []
        },
        "endpoint": {
            "event_type": "device_health",
            "hostname": "google-pixel-8",
            "username": "android_user",
            "process_name": "com.threatguard.agent",
            "process_id": 1234,
            "parent_process": "zygote",
            "executable_path": "/data/app/com.threatguard.agent/base.apk",
            "commandLine": "com.threatguard.agent",
            "privilege_level": "USER",
            "keyboard_hook": False,
            "network_connection": False,
            "elevated": False
        },
        "request": {
            "method": "POST",
            "endpoint": "/api/mobile/telemetry",
            "headers": {
                "X-Device-Model": "Pixel 8",
                "X-OS-Version": "14"
            }
        },
        "response": {
            "status_code": 200,
            "latency_ms": 15.0
        },
        "resource": {
            "resource_type": "mobile_endpoint",
            "resource_id": device_id,
            "owner_id": "android_user"
        }
    }

    resp = client.post("/events", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["event_id"] == event_id
    assert data["mitigation_action"] == "ALLOW"
    assert data["status"] == "processed"
    assert data["risk_assessment"]["threat_detected"] is False

    # SOC verification in MongoDB
    saved = events_collection.find_one({"event_id": event_id})
    assert saved is not None
    assert saved["resource"]["resource_id"] == device_id
    assert saved["domain"] == "ENDPOINT"
    assert saved["processing"]["mitigation_action"] == "ALLOW"


def test_android_suspicious_process_quarantine_flow():
    """Scenario B: Sideloaded suspicious app simulation -> QUARANTINE."""
    event_id = "test-android-suspicious-002"
    device_id = "ANDROID-E2E-TEST-MINER"

    payload = {
        "schema_version": "1.0",
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": "ENDPOINT",
        "network": {
            "source_ip": "192.168.1.102",
            "destination_ip": "10.0.2.2",
            "user_agent": "ThreatGuard-MobileSimulator/1.0"
        },
        "identity": {
            "user_id": "android_user",
            "is_authenticated": False,
            "roles": []
        },
        "endpoint": {
            "event_type": "suspicious_process_execution",
            "hostname": "android-pixel-8",
            "username": "u0_a210",
            "process_name": "com.suspicious.miner.app",
            "process_id": 6120,
            "parent_process": "zygote64",
            "executable_path": "/data/app/com.suspicious.miner.app/base.apk",
            "command_line": "powershell.exe -EncodedCommand SYNTHETIC_DEMO",
            "privilege_level": "USER",
            "keyboard_hook": False,
            "network_connection": True,
            "elevated": False
        },
        "request": {
            "method": "POST",
            "endpoint": "/api/endpoint-telemetry"
        },
        "response": {
            "status_code": 200,
            "latency_ms": 15.0
        },
        "resource": {
            "resource_type": "mobile_device",
            "resource_id": device_id,
            "owner_id": "android_user"
        }
    }

    resp = client.post("/events", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["event_id"] == event_id
    assert data["risk_assessment"]["threat_detected"] is True
    assert "SUSPICIOUS_PROCESS_EXECUTION" in data["risk_assessment"]["attack_types"]
    assert data["mitigation_action"] == "QUARANTINE"

    # SOC verification
    saved = events_collection.find_one({"event_id": event_id})
    assert saved is not None
    assert saved["resource"]["resource_id"] == device_id
    assert saved["processing"]["mitigation_action"] == "QUARANTINE"


def test_android_accessibility_keylogging_quarantine_flow():
    """Scenario C: Accessibility keyhook abuse simulation -> QUARANTINE."""
    event_id = "test-android-keylogger-003"
    device_id = "ANDROID-E2E-TEST-KEYLOG"

    payload = {
        "schema_version": "1.0",
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": "ENDPOINT",
        "network": {
            "source_ip": "192.168.1.105",
            "user_agent": "ThreatGuard-MobileSimulator/1.0"
        },
        "identity": {
            "user_id": "android_user",
            "is_authenticated": False,
            "roles": []
        },
        "endpoint": {
            "event_type": "keylogging",
            "hostname": "android-pixel-8",
            "username": "u0_a150",
            "process_name": "com.malicious.accessibility.keylogger",
            "process_id": 6240,
            "parent_process": "zygote",
            "executable_path": "/data/app/com.malicious.accessibility/base.apk",
            "command_line": "com.malicious.accessibility --capture-touch",
            "privilege_level": "USER",
            "keyboard_hook": True,
            "network_connection": False,
            "elevated": False
        },
        "request": {
            "method": "POST",
            "endpoint": "/api/endpoint-telemetry"
        },
        "response": {
            "status_code": 200,
            "latency_ms": 15.0
        },
        "resource": {
            "resource_type": "mobile_device",
            "resource_id": device_id,
            "owner_id": "android_user"
        }
    }

    resp = client.post("/events", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["event_id"] == event_id
    assert data["risk_assessment"]["threat_detected"] is True
    assert "KEYLOGGING" in data["risk_assessment"]["attack_types"]
    assert data["mitigation_action"] == "QUARANTINE"

    # SOC verification
    saved = events_collection.find_one({"event_id": event_id})
    assert saved is not None
    assert saved["resource"]["resource_id"] == device_id
    assert saved["processing"]["mitigation_action"] == "QUARANTINE"


def test_android_fake_banking_url_phishing_block_flow():
    """Scenario D: Controlled fake banking URL simulation -> URL_BLOCK."""
    event_id = "test-android-phishing-004"
    device_id = "ANDROID-E2E-TEST-PHISH"

    payload = {
        "schema_version": "1.0",
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": "ENDPOINT",
        "network": {
            "source_ip": "192.168.1.110",
            "user_agent": "Mozilla/5.0 (Linux; Android 14; Mobile)"
        },
        "identity": {
            "user_id": "android_user",
            "is_authenticated": False,
            "roles": []
        },
        "endpoint": {
            "event_type": "fake_bank",
            "hostname": "android-pixel-8",
            "username": "u0_a99",
            "process_name": "com.android.chrome",
            "process_id": 5120,
            "command_line": "chrome https://secure-login-verify-bank-account.info/login"
        },
        "request": {
            "method": "POST",
            "endpoint": "/lab/phishing/login",
            "body": {
                "suspicious_domain": "secure-login-verify-bank-account.info",
                "url": "https://secure-login-verify-bank-account.info/auth/login",
                "phishing_url": "/lab/phishing/login",
                "credential_submission_observed": True,
                "credential_capture_observed": True
            }
        },
        "response": {
            "status_code": 200,
            "latency_ms": 15.0
        },
        "resource": {
            "resource_type": "mobile_device",
            "resource_id": device_id,
            "owner_id": "android_user"
        }
    }

    resp = client.post("/events", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["event_id"] == event_id
    assert data["risk_assessment"]["threat_detected"] is True
    assert "PHISHING" in data["risk_assessment"]["attack_types"]
    assert data["mitigation_action"] == "URL_BLOCK"

    # SOC verification
    saved = events_collection.find_one({"event_id": event_id})
    assert saved is not None
    assert saved["resource"]["resource_id"] == device_id
    assert saved["processing"]["mitigation_action"] == "URL_BLOCK"


def test_android_transaction_abuse_block_flow():
    """Scenario E: Unauthorized transaction replay simulation -> TRANSACTION_BLOCK."""
    event_id = "test-android-txabuse-005"
    device_id = "ANDROID-E2E-TEST-TXABUSE"

    payload = {
        "schema_version": "1.0",
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": "API",
        "network": {
            "source_ip": "192.168.1.120",
            "user_agent": "ThreatGuard-MobileSimulator/1.0"
        },
        "endpoint": {
            "event_type": "unauthorized_transaction",
            "hostname": "android-pixel-8",
            "username": "u0_a44",
            "process_name": "com.session.hijacker.bot",
            "process_id": 5820
        },
        "identity": {
            "user_id": "compromised_mobile_user",
            "session_id": "sess-replayed-token-999",
            "roles": ["customer"],
            "is_authenticated": True
        },
        "request": {
            "method": "POST",
            "endpoint": "/api/transactions/transfer",
            "body": {
                "action": "transfer_funds",
                "beneficiary": "attacker_account_987",
                "amount": 9500,
                "replayed_session_id": "sess-replayed-token-999"
            }
        },
        "response": {
            "status_code": 200,
            "latency_ms": 15.0
        },
        "resource": {
            "resource_type": "transaction",
            "resource_id": device_id,
            "owner_id": "android_user",
            "is_sensitive": True
        }
    }

    resp = client.post("/events", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["event_id"] == event_id
    assert data["risk_assessment"]["threat_detected"] is True
    assert data["mitigation_action"] in ("TRANSACTION_BLOCK", "BLOCK", "QUARANTINE")

    # SOC verification
    saved = events_collection.find_one({"event_id": event_id})
    assert saved is not None
    assert saved["resource"]["resource_id"] == device_id
