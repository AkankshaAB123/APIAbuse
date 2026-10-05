"""Indicators for server-side request forgery (SSRF) attempts."""

# Rule version identifier
SSRF_RULE_VERSION = "1.0"

# Field names that are commonly used to carry URLs in API payloads.
# Existing hints are retained and expanded conservatively.
SSRF_URL_FIELD_HINTS = frozenset({
    "url",
    "uri",
    "webhook",
    "callback",
    "callback_url",
    "redirect",
    "image",
    # Expanded hints for broader coverage in demos
    "dest",
    "destination",
    "target",
    "feed",
    "source",
    "endpoint",
    "host",
    "domain",
    "proxy",
    "download",
    "import",
})

# Known cloud‑metadata endpoints – these are high‑severity SSRF targets.
CLOUD_METADATA_HOSTS = frozenset({
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.azure.internal",
    # Additional internal demo‑environment hosts (conservative list)
    "host.docker.internal",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
    "100.100.100.200",
    "fd00:ec2::254",
})

# Restricted protocols that are indicative of SSRF attempts even without host analysis.
RESTRICTED_PROTOCOLS = frozenset({"file", "gopher", "dict", "ftp", "ldap"})
