"""Individual detector implementations live in this package."""

from .bola_idor import detect_bola_idor
from .account_takeover import detect_account_takeover
from .broken_function_level_authorization import (
    detect_broken_function_level_authorization,
)
from .credential_attacks import detect_credential_attacks
from .sql_injection import detect_sql_injection

__all__ = [
    "detect_account_takeover",
    "detect_bola_idor",
    "detect_broken_function_level_authorization",
    "detect_credential_attacks",
    "detect_sql_injection",
]
