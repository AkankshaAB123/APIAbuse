"""Rules and signatures for malicious URLs."""

MALICIOUS_URL_PATTERNS = [
    ("MAL_URL_IP_BASED", r"https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?(?:/.*)?"),
    ("MAL_URL_KNOWN_BAD", r"evil\.com|malicious-domain\.org|phishing-site\.net"),
    ("MAL_URL_OBFUSCATED", r"https?://.*(?:%[0-9A-Fa-f]{2}){5,}.*"),
    ("MAL_URL_SUSPICIOUS_TLD", r"https?://[a-zA-Z0-9-]+\.(?:tk|ml|ga|cf|gq)(?:/.*)?")
]

MALICIOUS_URL_RULE_VERSION = "1.0.0"
