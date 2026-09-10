from backend.schemas.api_security_event import ApiSecurityEvent
from backend.schemas.impact_assessment import ImpactAssessment
from backend.schemas.risk_assessment import RiskAssessment


class MitigationService:
    """
    Decides the recommended mitigation action based on risk level and tangible impact.
    Supported actions:
    - ALLOW: Benign or low-risk traffic
    - MONITOR: Suspicious medium-risk activity requiring observation
    - RATE_LIMIT: High-risk volumetric or automated attacks
    - BLOCK: Critical generic infrastructure / API attacks
    - QUARANTINE: Endpoint compromise, malicious binaries, host threats
    - TRANSACTION_BLOCK: Financial loss, checkout / payment / coupon abuse
    - URL_BLOCK: Phishing, malicious redirect, or SSRF targeting suspicious URLs
    """

    def decide_action(
        self,
        risk_assessment: RiskAssessment,
        impact_assessment: ImpactAssessment | None = None,
        event: ApiSecurityEvent | None = None,
    ) -> str:
        """Decide the recommended mitigation action based on risk and impact."""

        if not risk_assessment.threat_detected:
            return "ALLOW"

        primary_impact = (
            impact_assessment.primary_impact
            if impact_assessment is not None
            else None
        )

        # 1. Endpoint compromise -> QUARANTINE
        if (
            primary_impact == "endpoint compromise"
            or (event is not None and event.domain == "ENDPOINT")
            or any(
                at in {
                    "KEYLOGGING",
                    "SUSPICIOUS_PROCESS_EXECUTION",
                    "REVERSE_SHELL",
                    "PRIVILEGE_ESCALATION",
                }
                for at in risk_assessment.attack_types
            )
        ):
            return "QUARANTINE"

        # 2. Financial loss / transaction abuse -> TRANSACTION_BLOCK
        if (
            primary_impact == "financial loss"
            or "BUSINESS_FLOW_ABUSE" in risk_assessment.attack_types
        ):
            return "TRANSACTION_BLOCK"

        # 3. Phishing / Malicious URL -> URL_BLOCK
        if (
            primary_impact == "malicious url"
            or any(
                "phishing" in r.lower()
                or "malicious url" in r.lower()
                or "malicious_url" in r.lower()
                for r in risk_assessment.reasons
            )
        ):
            return "URL_BLOCK"

        # 4. Standard risk-based fallback (e.g. SQL Injection, BOLA, SSRF, DoS)
        if risk_assessment.risk_level == "CRITICAL":
            return "BLOCK"

        if risk_assessment.risk_level == "HIGH":
            return "RATE_LIMIT"

        if risk_assessment.risk_level == "MEDIUM":
            return "MONITOR"

        return "ALLOW"