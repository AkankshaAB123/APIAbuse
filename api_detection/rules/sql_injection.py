"""Patterns used to identify likely SQL injection attempts in API input."""

SQL_INJECTION_RULE_VERSION = "1.0"

# These are detection signatures, not executable SQL. They focus on combinations
# that are very unlikely in ordinary API parameters.
SQL_INJECTION_PATTERNS = (
    (
        "BOOLEAN_TAUTOLOGY",
        r"(?:'|\")\s*(?:or|and)\s+(?:\d+\s*=\s*\d+|'[^']*'\s*=\s*'[^']*'|\"[^\"]*\"\s*=\s*\"[^\"]*\")",
    ),
    (
        "SQL_COMMENT",
        r"(?:'|\"|;)\s*(?:--|/\*)",
    ),
    (
        "UNION_SELECT",
        r"\bunion\s+(?:all\s+|distinct\s+)?select\b",
    ),
    (
        "DATA_MANIPULATION",
        r"\b(?:drop|insert|update|delete|truncate|alter)\s+(?:table|into|from|set)\b",
    ),
    (
        "DATABASE_METADATA",
        r"\b(?:information_schema|sys\.tables|sysobjects|pg_catalog)\b",
    ),
    (
        "TIME_BASED",
        r"\b(?:waitfor\s+delay\s+['\"][^'\"]+['\"]|(?:sleep|pg_sleep)\s*\(\s*\d+(?:\.\d+)?\s*\))",
    ),
)
