from api_detection.backend_adapter import run_for_backend


# =========================================================
# EVENT 2: Broken Function-Level Authorization
# =========================================================

event = {
    "schema_version": "1.0",
    "event_id": "evt-test-002",
    "timestamp": "2026-09-02T10:05:00Z",

    "network": {
        "source_ip": "192.168.1.77",
        "user_agent": "demo-client/1.0"
    },

    "identity": {
        "user_id": "user_17",
        "session_id": "session_123",
        "roles": ["customer"],
        "is_authenticated": True
    },

    "request": {
        "method": "GET",
        "endpoint": "/api/admin/users",
        "path_params": {},
        "query_params": {},
        "headers": {},
        "body": {}
    },

    "response": {
        "status_code": 403,
        "latency_ms": 20.0
    },

    "resource": {
        "resource_type": "admin_resource",
        "resource_id": None,
        "owner_id": None,
        "is_sensitive": True
    }
}


# =========================================================
# PREVIOUS EVENTS
# =========================================================

recent_events = []


# =========================================================
# RUN ALL 10 API ATTACK DETECTORS
# =========================================================

results = run_for_backend(
    event,
    recent_events
)


# =========================================================
# PRINT RESULTS
# =========================================================

print("\n========== API ATTACK DETECTION RESULTS ==========\n")

for result in results:
    print(result)

print("\n==================================================")