"""Patterns used to identify likely SQL injection attempts in API input."""

SQL_INJECTION_RULE_VERSION = "1.0"

# These are detection signatures, not executable SQL. They focus on combinations
# that are very unlikely in ordinary API parameters.
SQL_INJECTION_PATTERNS = (
    ("BOOLEAN_TAUTOLOGY", r"(?:'|\")\s*(?:or|and)\s+\d+\s*=\s*\d+"),
    ("SQL_COMMENT", r"(?:--|/\*)"),
    ("UNION_SELECT", r"\bunion\s+(?:all\s+)?select\b"),
    ("DATA_MANIPULATION", r"\b(?:drop|insert|update|delete)\s+(?:table|into|from|set)\b"),
    ("DATABASE_METADATA", r"\binformation_schema\b"),
)
