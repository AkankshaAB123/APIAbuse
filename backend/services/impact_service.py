from typing import Any

from backend.schemas.api_security_event import ApiSecurityEvent
from backend.schemas.detector_result import DetectorResult
from backend.schemas.impact_assessment import ImpactAssessment
from backend.schemas.ml_result import MLResult
from backend.schemas.risk_assessment import RiskAssessment


class ImpactService:
    """
    Deterministic Impact Assessment Engine.
    Evaluates tangible consequences of detected threats:
    - financial loss
    - credential compromise
    - account takeover
    - endpoint compromise
    - data exposure
    - unauthorized access
    - service disruption
    """

    FINANCIAL_KEYWORDS = {
        "order", "orders", "checkout", "transfer", "transfers",
        "payment", "payments", "pay", "cart", "coupon", "coupons",
        "discount", "discounts", "refund", "refunds", "wallet",
        "billing", "purchase", "purchases", "pricing", "checkout-step"
    }

    IMPACT_PRIORITY = [
        "endpoint compromise",
        "financial loss",
        "account takeover",
        "credential compromise",
        "unauthorized access",
        "data exposure",
        "service disruption",
        "malicious url",
    ]

    def assess(
        self,
        event: ApiSecurityEvent,
        detector_results: list[DetectorResult] | None = None,
        risk_assessment: RiskAssessment | None = None,
        ml_result: MLResult | None = None,
    ) -> ImpactAssessment:
        detector_results = detector_results or []
        detected_results = [r for r in detector_results if r.detected]

        ml_threat = False
        ml_prediction = ""
        ml_is_anomaly = False
        if ml_result is not None:
            ml_prediction = (ml_result.detection.prediction or "").strip()
            ml_is_anomaly = bool(ml_result.anomaly.is_anomaly)
            ml_threat = (
                ml_prediction.upper() != "BENIGN" and bool(ml_prediction)
            ) or ml_is_anomaly

        threat_detected = (
            (risk_assessment is not None and risk_assessment.threat_detected)
            or bool(detected_results)
            or ml_threat
        )

        if not threat_detected:
            return ImpactAssessment(
                impact_identified=False,
                categories=[],
                primary_impact=None,
                severity="LOW",
                reasons=["No threats detected; operations within normal baseline."],
                details={},
            )

        categories: list[str] = []
        reasons: list[str] = []

        attack_types = set()
        if risk_assessment and risk_assessment.attack_types:
            attack_types.update(risk_assessment.attack_types)
        for r in detected_results:
            if r.attack_type:
                attack_types.add(r.attack_type)

        detector_ids = {r.detector_id for r in detected_results}

        # 1. Endpoint Compromise
        is_endpoint = (
            bool(
                attack_types.intersection(
                    {
                        "KEYLOGGING",
                        "SUSPICIOUS_PROCESS_EXECUTION",
                        "REVERSE_SHELL",
                        "PRIVILEGE_ESCALATION",
                    }
                )
            )
            or bool(
                detector_ids.intersection(
                    {
                        "keylogging",
                        "suspicious_process_execution",
                        "reverse_shell",
                        "privilege_escalation",
                    }
                )
            )
        )
        if is_endpoint:
            categories.append("endpoint compromise")
            reasons.append("Endpoint host or execution environment compromised.")

        # 2. Account Takeover
        is_ato = (
            "ACCOUNT_TAKEOVER" in attack_types
            or "account_takeover" in detector_ids
        )
        if is_ato:
            categories.append("account takeover")
            reasons.append("Targeted session or user account subjected to unauthorized takeover.")

        # 3. Credential Compromise
        is_cred = (
            bool(
                attack_types.intersection(
                    {"CREDENTIAL_ATTACK", "NETWORK_BRUTE_FORCE"}
                )
            )
            or bool(
                detector_ids.intersection(
                    {"credential_attack", "network_brute_force"}
                )
            )
        )
        if is_cred:
            categories.append("credential compromise")
            reasons.append("User or system credentials targeted by brute-force, stuffing, or credential theft.")

        # 4. Financial Loss
        endpoint_lower = (event.request.endpoint or "").lower()
        endpoint_segments = set(
            part
            for part in endpoint_lower.replace("-", "/").replace("_", "/").split("/")
            if part
        )
        has_financial_endpoint = bool(
            endpoint_segments.intersection(self.FINANCIAL_KEYWORDS)
        )
        is_business_flow = (
            "BUSINESS_FLOW_ABUSE" in attack_types
            or "business_flow_abuse" in detector_ids
        )
        if is_business_flow or (has_financial_endpoint and threat_detected):
            categories.append("financial loss")
            reasons.append("Business flow abuse or fraudulent operation targeting transactional/financial workflow.")

        # 5. Unauthorized Access
        is_unauth = (
            bool(
                attack_types.intersection(
                    {
                        "BOLA_IDOR",
                        "BROKEN_FUNCTION_LEVEL_AUTHORIZATION",
                        "PRIVILEGE_ESCALATION",
                    }
                )
            )
            or bool(
                detector_ids.intersection(
                    {
                        "bola_idor",
                        "broken_function_level_authorization",
                        "privilege_escalation",
                    }
                )
            )
        )
        if is_unauth:
            categories.append("unauthorized access")
            reasons.append("Unauthorized object, function, or elevated privilege access attempted.")

        # 6. Data Exposure
        is_data_exposure = (
            bool(
                attack_types.intersection(
                    {
                        "SQL_INJECTION",
                        "SSRF",
                        "ENDPOINT_ENUMERATION",
                        "PORT_SCANNING",
                    }
                )
            )
            or bool(
                detector_ids.intersection(
                    {
                        "sql_injection",
                        "ssrf",
                        "endpoint_enumeration",
                        "port_scanning",
                    }
                )
            )
        )
        if is_data_exposure:
            categories.append("data exposure")
            reasons.append("Sensitive data exfiltration, backend discovery, or injection exposure risk.")

        # 7. Service Disruption
        is_disruption = (
            bool(
                attack_types.intersection(
                    {
                        "DDOS",
                        "DOS_FLOODING",
                        "RESOURCE_EXHAUSTION",
                    }
                )
            )
            or bool(
                detector_ids.intersection(
                    {
                        "ddos",
                        "dos_flooding",
                        "resource_exhaustion",
                    }
                )
            )
        )
        if is_disruption:
            categories.append("service disruption")
            reasons.append("High volume requests or resource consumption threatening service availability.")

        # 8. Malicious / Phishing URL
        evidence_texts = [
            ev.message.lower()
            for r in detected_results
            for ev in r.evidence
        ]
        has_url_signal = (
            any(
                "phishing" in t
                or "malicious url" in t
                or "malicious_url" in t
                or "suspicious url" in t
                for t in evidence_texts
            )
            or "phishing" in str(event.request.query_params).lower()
            or "malicious_url" in str(event.request.query_params).lower()
        )
        if has_url_signal:
            categories.append("malicious url")
            reasons.append("Request contains suspicious or phishing URL reference.")

        # 9. ML Signal Threat / Anomaly Fallback
        if ml_threat:
            pred_upper = ml_prediction.upper()
            if "DDOS" in pred_upper or "DOS" in pred_upper:
                categories.append("service disruption")
                reasons.append(f"ML model predicted volumetric traffic attack: {ml_prediction}.")
            elif "PORTSCAN" in pred_upper or "SCAN" in pred_upper:
                categories.append("data exposure")
                reasons.append(f"ML model predicted network scanning/reconnaissance: {ml_prediction}.")
            elif "BRUTE" in pred_upper or "PATATOR" in pred_upper:
                categories.append("credential compromise")
                reasons.append(f"ML model predicted automated brute force: {ml_prediction}.")
            elif "INFILTRATION" in pred_upper or "BOT" in pred_upper:
                categories.append("endpoint compromise")
                reasons.append(f"ML model predicted host infiltration or bot activity: {ml_prediction}.")
            elif "SQL" in pred_upper:
                categories.append("data exposure")
                reasons.append(f"ML model predicted database injection: {ml_prediction}.")
            elif "XSS" in pred_upper or "WEB" in pred_upper:
                categories.append("unauthorized access")
                reasons.append(f"ML model predicted web exploit: {ml_prediction}.")
            elif ml_is_anomaly:
                categories.append("service disruption")
                reasons.append("ML anomaly detector identified anomalous network traffic flow.")
            elif pred_upper and pred_upper != "BENIGN":
                categories.append("unauthorized access")
                reasons.append(f"ML model identified unclassified security threat: {ml_prediction}.")

        # Fallback if threat was detected but none of above matched explicitly
        if not categories:
            categories.append("unauthorized access")
            reasons.append("Unclassified security violation detected requiring defensive action.")

        # Deduplicate preserving order
        unique_categories = list(dict.fromkeys(categories))
        unique_reasons = list(dict.fromkeys(reasons))

        # Determine primary impact based on strict priority
        primary_impact = None
        for prio in self.IMPACT_PRIORITY:
            if prio in unique_categories:
                primary_impact = prio
                break
        if not primary_impact and unique_categories:
            primary_impact = unique_categories[0]

        # Determine severity
        severity = "LOW"
        if risk_assessment:
            severity = risk_assessment.risk_level
        elif ml_threat:
            severity = "HIGH" if (ml_result and ml_result.detection.confidence >= 0.75) else "MEDIUM"

        highest_detector_severity = "LOW"
        severity_ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        for r in detected_results:
            det_sev = str(r.severity).upper()
            if severity_ranks.get(det_sev, 0) > severity_ranks.get(highest_detector_severity, 0):
                highest_detector_severity = det_sev
        if severity_ranks.get(highest_detector_severity, 0) > severity_ranks.get(severity, 0):
            severity = highest_detector_severity

        return ImpactAssessment(
            impact_identified=True,
            categories=unique_categories,
            primary_impact=primary_impact,
            severity=severity,
            reasons=unique_reasons,
            details={
                "attack_types": list(attack_types),
                "detector_ids": list(detector_ids),
                "domain": event.domain,
                "ml_prediction": ml_prediction if ml_threat else None,
                "ml_anomaly": ml_is_anomaly,
            },
        )
