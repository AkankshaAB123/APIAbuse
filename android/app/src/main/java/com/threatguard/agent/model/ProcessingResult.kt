package com.threatguard.agent.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

@Serializable
data class RiskAssessment(
    @SerialName("risk_score") val riskScore: Double = 0.0,
    @SerialName("risk_level") val riskLevel: String = "LOW",
    @SerialName("threat_detected") val threatDetected: Boolean = false,
    @SerialName("attack_types") val attackTypes: List<String> = emptyList(),
    @SerialName("reasons") val reasons: List<String> = emptyList(),
    @SerialName("detector_count") val detectorCount: Int = 0
)

@Serializable
data class ImpactAssessment(
    @SerialName("impact_identified") val impactIdentified: Boolean = false,
    @SerialName("primary_impact") val primaryImpact: String? = null,
    @SerialName("categories") val categories: List<String> = emptyList(),
    @SerialName("severity") val severity: String = "LOW",
    @SerialName("reasons") val reasons: List<String> = emptyList()
)

@Serializable
data class AiAnalysis(
    @SerialName("threat_explanation") val threatExplanation: String? = null,
    @SerialName("evidence") val evidence: String? = null,
    @SerialName("risk_assessment") val riskAssessmentText: String? = null,
    @SerialName("recommended_action") val recommendedAction: String? = null,
    @SerialName("confidence_level") val confidenceLevel: String? = "UNKNOWN",
    @SerialName("error") val error: String? = null
)

@Serializable
data class DetectionEvidence(
    @SerialName("code") val code: String = "",
    @SerialName("message") val message: String = ""
)

@Serializable
data class DetectorResult(
    @SerialName("detector_id") val detectorId: String,
    @SerialName("detected") val detected: Boolean = false,
    @SerialName("attack_type") val attackType: String? = null,
    @SerialName("confidence") val confidence: Double = 0.0,
    @SerialName("severity") val severity: String = "LOW",
    @SerialName("source") val source: String = "api_detector",
    @SerialName("domain") val domain: String = "API",
    @SerialName("evidence") val evidence: List<DetectionEvidence> = emptyList()
)

@Serializable
data class ProcessingResult(
    @SerialName("event_id") val eventId: String,
    @SerialName("source_ip") val sourceIp: String? = null,
    @SerialName("status") val status: String = "processed",
    @SerialName("message") val message: String? = null,
    @SerialName("mitigation_action") val mitigationAction: String = "ALLOW",
    @SerialName("detector_results") val detectorResults: List<DetectorResult> = emptyList(),
    @SerialName("risk_assessment") val riskAssessment: RiskAssessment? = null,
    @SerialName("impact") val impact: ImpactAssessment? = null,
    @SerialName("ai_analysis") val aiAnalysis: JsonElement? = null
)

