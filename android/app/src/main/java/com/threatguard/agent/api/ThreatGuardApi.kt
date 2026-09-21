package com.threatguard.agent.api

import com.threatguard.agent.model.ApiSecurityEvent
import com.threatguard.agent.model.ProcessingResult
import com.threatguard.agent.model.ThreatDetail
import com.threatguard.agent.model.ThreatSummary
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.concurrent.TimeUnit

import com.threatguard.agent.model.LoginRequest
import com.threatguard.agent.model.TokenResponse

class ThreatGuardApi(
    private var baseUrl: String = "http://10.0.2.2:8000/",
    private var authToken: String? = null
) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .writeTimeout(15, TimeUnit.SECONDS)
        .build()

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        prettyPrint = false
        isLenient = true
    }

    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()

    fun updateBaseUrl(newUrl: String) {
        var cleanUrl = newUrl.trim()
        if (!cleanUrl.endsWith("/")) {
            cleanUrl += "/"
        }
        this.baseUrl = cleanUrl
    }

    fun updateAuthToken(token: String?) {
        this.authToken = token
    }

    fun getBaseUrl(): String = baseUrl

    fun getAuthToken(): String? = authToken

    suspend fun login(username: String, password: String): Result<TokenResponse> = withContext(Dispatchers.IO) {
        try {
            val endpointUrl = baseUrl + "auth/login"
            val loginPayload = json.encodeToString(LoginRequest.serializer(), LoginRequest(username, password))
            val requestBody = loginPayload.toRequestBody(jsonMediaType)

            val request = Request.Builder()
                .url(endpointUrl)
                .post(requestBody)
                .addHeader("Accept", "application/json")
                .addHeader("Content-Type", "application/json")
                .build()

            client.newCall(request).execute().use { response ->
                val responseBody = response.body?.string() ?: ""
                if (!response.isSuccessful) {
                    return@withContext Result.failure(
                        IOException("HTTP ${response.code}: $responseBody")
                    )
                }

                try {
                    val tokenResp = json.decodeFromString(TokenResponse.serializer(), responseBody)
                    updateAuthToken(tokenResp.accessToken)
                    Result.success(tokenResp)
                } catch (e: Exception) {
                    Result.failure(IOException("Failed to parse TokenResponse: ${e.message}", e))
                }
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun testConnection(): Result<String> = withContext(Dispatchers.IO) {
        try {
            val request = Request.Builder()
                .url(baseUrl)
                .get()
                .build()

            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val body = response.body?.string() ?: ""
                    Result.success("Connected successfully (HTTP ${response.code}): $body")
                } else {
                    Result.failure(IOException("Server responded with HTTP ${response.code}"))
                }
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun postEvent(event: ApiSecurityEvent): Result<ProcessingResult> = withContext(Dispatchers.IO) {
        try {
            val endpointUrl = baseUrl + "events"
            val jsonPayload = json.encodeToString(ApiSecurityEvent.serializer(), event)
            val requestBody = jsonPayload.toRequestBody(jsonMediaType)

            val request = Request.Builder()
                .url(endpointUrl)
                .post(requestBody)
                .addHeader("Accept", "application/json")
                .addHeader("Content-Type", "application/json")
                .build()

            client.newCall(request).execute().use { response ->
                val responseBody = response.body?.string() ?: ""
                if (!response.isSuccessful) {
                    return@withContext Result.failure(
                        IOException("HTTP ${response.code}: $responseBody")
                    )
                }

                try {
                    val result = json.decodeFromString(ProcessingResult.serializer(), responseBody)
                    Result.success(result)
                } catch (e: Exception) {
                    Result.failure(IOException("Failed to parse ProcessingResult: ${e.message}", e))
                }
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun getThreats(): Result<List<ThreatSummary>> = withContext(Dispatchers.IO) {
        try {
            val endpointUrl = baseUrl + "threats"
            val requestBuilder = Request.Builder()
                .url(endpointUrl)
                .get()
                .addHeader("Accept", "application/json")

            if (!authToken.isNullOrBlank()) {
                requestBuilder.addHeader("Authorization", "Bearer $authToken")
            }

            client.newCall(requestBuilder.build()).execute().use { response ->
                val responseBody = response.body?.string() ?: ""
                if (!response.isSuccessful) {
                    return@withContext Result.failure(
                        IOException("HTTP ${response.code}: $responseBody")
                    )
                }

                try {
                    val list = json.decodeFromString(
                        ListSerializer(ThreatSummary.serializer()),
                        responseBody
                    )
                    Result.success(list)
                } catch (e: Exception) {
                    Result.failure(IOException("Failed to parse threats list: ${e.message}", e))
                }
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun getThreatDetail(eventId: String): Result<ThreatDetail> = withContext(Dispatchers.IO) {
        try {
            val endpointUrl = baseUrl + "threats/" + eventId
            val requestBuilder = Request.Builder()
                .url(endpointUrl)
                .get()
                .addHeader("Accept", "application/json")

            if (!authToken.isNullOrBlank()) {
                requestBuilder.addHeader("Authorization", "Bearer $authToken")
            }

            client.newCall(requestBuilder.build()).execute().use { response ->
                val responseBody = response.body?.string() ?: ""
                if (!response.isSuccessful) {
                    return@withContext Result.failure(
                        IOException("HTTP ${response.code}: $responseBody")
                    )
                }

                try {
                    val detail = json.decodeFromString(ThreatDetail.serializer(), responseBody)
                    Result.success(detail)
                } catch (e: Exception) {
                    Result.failure(IOException("Failed to parse threat detail: ${e.message}", e))
                }
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
