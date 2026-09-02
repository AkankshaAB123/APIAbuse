"""Individual detector implementations live in this package."""

from .account_takeover import detect_account_takeover
from .bola_idor import detect_bola_idor
from .broken_function_level_authorization import (
    detect_broken_function_level_authorization,
)
from .business_flow_abuse import detect_business_flow_abuse
from .credential_attacks import detect_credential_attacks
from .endpoint_enumeration import detect_endpoint_enumeration
from .resource_exhaustion import detect_resource_exhaustion
from .security_misconfiguration import (
    detect_security_misconfiguration,
)
from .sql_injection import detect_sql_injection
from .ssrf import detect_ssrf


__all__ = [
    "detect_account_takeover",
    "detect_bola_idor",
    "detect_broken_function_level_authorization",
    "detect_business_flow_abuse",
    "detect_credential_attacks",
    "detect_endpoint_enumeration",
    "detect_resource_exhaustion",
    "detect_security_misconfiguration",
    "detect_sql_injection",
    "detect_ssrf",
]