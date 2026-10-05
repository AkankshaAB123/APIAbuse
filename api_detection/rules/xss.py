"""Patterns used to identify likely XSS attempts in API input."""

XSS_RULE_VERSION = "1.0"

# These signatures look for common cross-site scripting indicators.
XSS_PATTERNS = (
    ("SCRIPT_TAG", r"<\s*script[^>]*>"),
    ("EVENT_HANDLER", r"\bon[a-z]+\s*=\s*(?:\"|'|.*?(?=>))"),
    ("JAVASCRIPT_PROTOCOL", r"javascript\s*:"),
    ("HTML_INJECTION", r"<\s*(?:iframe|object|embed|svg|math)[^>]*>"),
)
