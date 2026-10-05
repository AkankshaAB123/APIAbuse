"""Rules for detecting business flow abuse."""

BUSINESS_FLOW_RULE_VERSION = "1.0"

# Number of repeated sensitive actions before detection.
BUSINESS_FLOW_THRESHOLD = 5

# Sensitive actions that may be abused when repeated excessively.
SENSITIVE_BUSINESS_ENDPOINTS = (
    "/checkout",
    "/redeem",
    "/apply-coupon",
    "/transfer",
    "/payment",
)