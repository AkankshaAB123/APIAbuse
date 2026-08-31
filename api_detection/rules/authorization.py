"""Authorization policy shared by BOLA and privilege-escalation detectors."""

PRIVILEGED_ROLES = frozenset({"admin", "service"})
BOLA_RULE_VERSION = "1.0"
