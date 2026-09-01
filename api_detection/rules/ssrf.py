"""Indicators for server-side request forgery (SSRF) attempts."""

SSRF_RULE_VERSION = "1.0"
SSRF_URL_FIELD_HINTS = frozenset({"url", "uri", "webhook", "callback", "redirect", "image"})
CLOUD_METADATA_HOSTS = frozenset({
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.azure.internal",
})
