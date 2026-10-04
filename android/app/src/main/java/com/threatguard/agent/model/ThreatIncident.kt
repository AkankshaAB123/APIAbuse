package com.threatguard.agent.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

@Serializable
data class ThreatSummary(
    @SerialName("id") val id: String,
    @SerialName("timestamp") val timestamp: String? = null,
    @SerialName("sourceIp") val sourceIp: String? = null,
    @SerialName("actualClientIp") val actualClientIp: String? = null,
    @SerialName("syntheticSourceIp") val syntheticSourceIp: String? = null,
    @SerialName("userId") val userId: String? = null,
    @SerialName("endpoint") val endpoint: String? = null,
    @SerialName("method") val method: String? = null,
    @SerialName("attackType") val attackType: String = "UNKNOWN",
    @SerialName("attackTypes") val attackTypes: List<String> = emptyList(),
    @SerialName("severity") val severity: String? = "LOW",
    @SerialName("riskScore") val riskScore: Double = 0.0,
    @SerialName("action") val action: String = "ALLOW",
    @SerialName("finalStatus") val finalStatus: String? = null,
    @SerialName("mitigationResult") val mitigationResult: String? = null,
    @SerialName("impactObserved") val impactObserved: Boolean? = null,
    @SerialName("classification") val classification: JsonElement? = null,
    @SerialName("threatDetected") val threatDetected: Boolean = false,
    @SerialName("detectorCount") val detectorCount: Int = 0,
    @SerialName("impact") val impact: ImpactAssessment? = null
)

@Serializable
data class ThreatDetail(
    @SerialName("_id") val mongoId: String? = null,
    @SerialName("event_id") val eventId: String,
    @SerialName("timestamp") val timestamp: String? = null,
    @SerialName("domain") val domain: String = "API",
    @SerialName("network") val network: NetworkInfo? = null,
    @SerialName("identity") val identity: IdentityInfo? = null,
    @SerialName("request") val request: RequestInfo? = null,
    @SerialName("response") val response: ResponseInfo? = null,
    @SerialName("resource") val resource: ResourceInfo? = null,
    @SerialName("endpoint") val endpoint: EndpointInfo? = null,
    @SerialName("processing") val processing: ProcessingResult? = null,
    @SerialName("impact") val impact: ImpactAssessment? = null
)
