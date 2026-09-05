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
from .ddos import detect_ddos
from .dos_flooding import detect_dos_flooding
from .network_brute_force import detect_network_brute_force
from .port_scanning import detect_port_scanning
from .keylogging import detect_keylogging
from .suspicious_process_execution import (
    detect_suspicious_process_execution,
)
from .reverse_shell import detect_reverse_shell
from .privilege_escalation import detect_privilege_escalation

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
    "detect_ddos",
    "detect_dos_flooding",
    "detect_network_brute_force",
    "detect_port_scanning",
    "detect_keylogging",
    "detect_suspicious_process_execution",
    "detect_reverse_shell",
    "detect_privilege_escalation",
]