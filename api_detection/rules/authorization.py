"""Authorization policy shared by BOLA and privilege-escalation detectors."""

PRIVILEGED_ROLES = frozenset({"admin", "service"})
BOLA_RULE_VERSION = "1.0"
BFLA_RULE_VERSION = "1.0"

# Public/system identifiers where individual resource ownership is not applicable
NON_OWNED_IDENTIFIERS = frozenset({
    "public",
    "none",
    "system",
    "unowned",
    "anonymous",
    "shared",
})

# Keep this policy separate from detector code so it can later be loaded from
# the backend configuration instead of requiring detector changes.
PRIVILEGED_ENDPOINT_PREFIXES = (
    "/api/admin/",
    "/api/internal/",
    "/api/management/",
)
