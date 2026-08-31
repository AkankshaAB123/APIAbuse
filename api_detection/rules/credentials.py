"""Thresholds and endpoint patterns for credential-attack detection."""

CREDENTIAL_RULE_VERSION = "1.0"
AUTH_WINDOW_SECONDS = 300
FAILED_AUTH_STATUS_CODES = frozenset({401, 403})
LOGIN_ENDPOINT_PREFIXES = ("/api/auth/login", "/api/login", "/auth/login")
BRUTE_FORCE_THRESHOLD = 5
CREDENTIAL_STUFFING_ACCOUNT_THRESHOLD = 3
