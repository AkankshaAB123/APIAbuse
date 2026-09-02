event = {
    "schema_version": "1.0",
    "event_id": "evt-privilege-001",
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
        "resource_type": None,
        "resource_id": None,
        "owner_id": None,
        "is_sensitive": True
    }
}

recent_events = []

results = run_for_backend(
    event,
    recent_events
)

for result in results:
    print(result)