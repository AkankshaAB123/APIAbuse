"""Individual detector implementations live in this package."""

from .bola_idor import detect_bola_idor
from .broken_function_level_authorization import (
    detect_broken_function_level_authorization,
)
from .credential_attacks import detect_credential_attacks

__all__ = [
    "detect_bola_idor",
    "detect_broken_function_level_authorization",
    "detect_credential_attacks",
]
