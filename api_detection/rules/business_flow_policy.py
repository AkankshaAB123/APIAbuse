"""Policy configuration for detecting business flow abuse."""

BUSINESS_FLOW_RULE_VERSION = "1.0"

# Number of repeated sensitive operations allowed
# before the behaviour is considered suspicious.
MAX_REPEATED_SENSITIVE_ACTIONS = 5

# Endpoints representing sensitive business operations.
SENSITIVE_BUSINESS_ENDPOINTS = (
    "/api/orders/checkout",
    "/api/payments",
    "/api/coupons/apply",
    "/api/refunds",
)