"""Thresholds for resource-exhaustion detection."""

RESOURCE_EXHAUSTION_RULE_VERSION = "1.0"

# Maximum number of requests from the same source IP to the same endpoint
# before the traffic is considered suspicious.
REQUEST_THRESHOLD = 10

# Window size included in detector metadata.
REQUEST_WINDOW_SECONDS = 60