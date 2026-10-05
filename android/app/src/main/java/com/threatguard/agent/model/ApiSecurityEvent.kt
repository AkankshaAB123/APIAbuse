package com.threatguard.agent.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

@Serializable
data class NetworkInfo(
    @SerialName("source_ip") val sourceIp: String,
    @SerialName("user_agent") val userAgent: String? = null,
    @SerialName("destination_ip") val destinationIp: String? = null,
    @SerialName("source_port") val sourcePort: Int? = null,
    @SerialName("destination_port") val destinationPort: Int? = null,
    @SerialName("protocol") val protocol: String? = "TCP",
    @SerialName("bytes") val bytes: Int? = 512,
    @SerialName("packets") val packets: Int? = 4,
    @SerialName("connection_status") val connectionStatus: String? = "success"
)

@Serializable
data class EndpointInfo(
    @SerialName("event_type") val eventType: String? = null,
    @SerialName("hostname") val hostname: String? = null,
    @SerialName("username") val username: String? = null,
    @SerialName("process_name") val processName: String? = null,
    @SerialName("process_id") val processId: Int? = null,
    @SerialName("parent_process") val parentProcess: String? = null,
    @SerialName("executable_path") val executablePath: String? = null,
    @SerialName("command_line") val commandLine: String? = null,
    @SerialName("privilege_level") val privilegeLevel: String? = "USER",
    @SerialName("keyboard_hook") val keyboardHook: Boolean? = false,
    @SerialName("network_connection") val networkConnection: Boolean? = false,
    @SerialName("elevated") val elevated: Boolean? = false
)

@Serializable
data class IdentityInfo(
    @SerialName("user_id") val userId: String? = null,
    @SerialName("session_id") val sessionId: String? = null,
    @SerialName("roles") val roles: List<String> = emptyList(),
    @SerialName("is_authenticated") val isAuthenticated: Boolean = false
)

@Serializable
data class RequestInfo(
    @SerialName("method") val method: String = "GET",
    @SerialName("endpoint") val endpoint: String = "/api/mobile/telemetry",
    @SerialName("path_params") val pathParams: Map<String, String> = emptyMap(),
    @SerialName("query_params") val queryParams: Map<String, String> = emptyMap(),
    @SerialName("headers") val headers: Map<String, String> = emptyMap(),
    @SerialName("body") val body: JsonElement? = null
)

@Serializable
data class ResponseInfo(
    @SerialName("status_code") val statusCode: Int = 200,
    @SerialName("latency_ms") val latencyMs: Double? = 15.0
)

@Serializable
data class ResourceInfo(
    @SerialName("resource_type") val resourceType: String? = "mobile_device",
    @SerialName("resource_id") val resourceId: String? = null,
    @SerialName("owner_id") val ownerId: String? = null,
    @SerialName("is_sensitive") val isSensitive: Boolean = false
)

@Serializable
data class ApiSecurityEvent(
    @SerialName("schema_version") val schemaVersion: String = "1.0",
    @SerialName("event_id") val eventId: String,
    @SerialName("timestamp") val timestamp: String,
    @SerialName("domain") val domain: String = "ENDPOINT",
    @SerialName("network") val network: NetworkInfo,
    @SerialName("identity") val identity: IdentityInfo = IdentityInfo(),
    @SerialName("request") val request: RequestInfo = RequestInfo(),
    @SerialName("response") val response: ResponseInfo = ResponseInfo(),
    @SerialName("resource") val resource: ResourceInfo = ResourceInfo(),
    @SerialName("endpoint") val endpoint: EndpointInfo? = null
)
