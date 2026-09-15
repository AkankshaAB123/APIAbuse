package com.threatguard.agent

import com.threatguard.agent.model.ThreatDetail
import com.threatguard.agent.model.ThreatSummary
import com.threatguard.agent.notification.ThreatNotificationManager
import com.threatguard.agent.service.ThreatMonitor
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class ThreatNotificationTest {

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        isLenient = true
    }

    @Before
    fun setUp() {
        ThreatMonitor.resetState()
    }

    // 1. Severity -> Notification Behavior Tests
    @Test
    fun testThreatNotificationSeverityLogic() {
        val highThreat = ThreatSummary(
            id = "evt-high-1",
            attackType = "SQL_INJECTION",
            severity = "HIGH",
            riskScore = 88.0,
            action = "BLOCK"
        )
        assertTrue(ThreatNotificationManager.shouldNotifyForThreat(highThreat))

        val criticalThreat = ThreatSummary(
            id = "evt-crit-1",
            attackType = "SUSPICIOUS_PROCESS_EXECUTION",
            severity = "CRITICAL",
            riskScore = 95.0,
            action = "QUARANTINE"
        )
        assertTrue(ThreatNotificationManager.shouldNotifyForThreat(criticalThreat))

        val scoreThresholdThreat = ThreatSummary(
            id = "evt-score-1",
            attackType = "ANOMALY",
            severity = "MEDIUM",
            riskScore = 76.0,
            action = "MONITOR"
        )
        assertTrue(ThreatNotificationManager.shouldNotifyForThreat(scoreThresholdThreat))

        val mediumLowThreat = ThreatSummary(
            id = "evt-med-1",
            attackType = "RATE_LIMIT_HIT",
            severity = "MEDIUM",
            riskScore = 50.0,
            action = "RATE_LIMIT"
        )
        assertFalse(ThreatNotificationManager.shouldNotifyForThreat(mediumLowThreat))

        val lowThreat = ThreatSummary(
            id = "evt-low-1",
            attackType = "BENIGN",
            severity = "LOW",
            riskScore = 15.0,
            action = "ALLOW"
        )
        assertFalse(ThreatNotificationManager.shouldNotifyForThreat(lowThreat))
    }

    // 2. Backend JSON Parsing (/threats list)
    @Test
    fun testGetThreatsJsonDeserialization() {
        val jsonString = """
        [
            {
                "id": "evt-laptop-fake-bank-001",
                "timestamp": "2026-09-14T11:20:00Z",
                "sourceIp": "192.168.1.50",
                "endpoint": "/api/banking/login",
                "method": "GET",
                "attackType": "PHISHING",
                "severity": "HIGH",
                "riskScore": 92.5,
                "action": "URL_BLOCK",
                "threatDetected": true
            },
            {
                "id": "evt-laptop-cmd-002",
                "timestamp": "2026-09-14T11:21:00Z",
                "sourceIp": "192.168.1.50",
                "endpoint": "/api/endpoint-telemetry",
                "method": "POST",
                "attackType": "SUSPICIOUS_PROCESS_EXECUTION",
                "severity": "CRITICAL",
                "riskScore": 96.0,
                "action": "QUARANTINE",
                "threatDetected": true
            }
        ]
        """.trimIndent()

        val list = json.decodeFromString(ListSerializer(ThreatSummary.serializer()), jsonString)
        assertEquals(2, list.size)
        assertEquals("evt-laptop-fake-bank-001", list[0].id)
        assertEquals("PHISHING", list[0].attackType)
        assertEquals("URL_BLOCK", list[0].action)
        assertTrue(ThreatNotificationManager.shouldNotifyForThreat(list[0]))

        assertEquals("evt-laptop-cmd-002", list[1].id)
        assertEquals("QUARANTINE", list[1].action)
        assertTrue(ThreatNotificationManager.shouldNotifyForThreat(list[1]))
    }

    // 3. Incident Parsing (/threats/{id} full document with AI analysis and detector results)
    @Test
    fun testThreatDetailJsonDeserialization() {
        val detailJson = """
        {
            "_id": "66e57b98f1a2b3c4d5e6f7a8",
            "event_id": "evt-laptop-fake-bank-001",
            "timestamp": "2026-09-14T11:20:00Z",
            "domain": "API",
            "network": {
                "source_ip": "192.168.1.50",
                "user_agent": "Mozilla/5.0"
            },
            "endpoint": {
                "hostname": "victim-laptop",
                "process_name": "chrome.exe"
            },
            "processing": {
                "event_id": "evt-laptop-fake-bank-001",
                "status": "processed",
                "message": "Threat analyzed",
                "mitigation_action": "URL_BLOCK",
                "detector_results": [
                    {
                        "detector_id": "detect_phishing",
                        "detected": true,
                        "attack_type": "PHISHING",
                        "confidence": 0.95,
                        "severity": "HIGH",
                        "source": "api_detector",
                        "domain": "API",
                        "evidence": [
                            {"code": "PHISH_URL", "message": "Lookalike banking domain detected"}
                        ]
                    }
                ],
                "risk_assessment": {
                    "risk_score": 92.5,
                    "risk_level": "HIGH",
                    "threat_detected": true,
                    "attack_types": ["PHISHING"],
                    "detector_count": 1
                },
                "impact": {
                    "impact_identified": true,
                    "primary_impact": "Financial Loss / Credential Compromise",
                    "categories": ["FINANCIAL", "CREDENTIAL_COMPROMISE"],
                    "severity": "HIGH",
                    "reasons": ["Attempted credential phishing via lookalike domain"]
                },
                "ai_analysis": {
                    "threat_explanation": "User navigated to a credential harvesting site.",
                    "confidence_level": "HIGH",
                    "evidence": "Domain imitation of legitimate portal",
                    "recommended_action": "Block URL and invalidate user sessions"
                }
            }
        }
        """.trimIndent()

        val detail = json.decodeFromString(ThreatDetail.serializer(), detailJson)
        assertEquals("evt-laptop-fake-bank-001", detail.eventId)
        assertEquals("API", detail.domain)
        assertEquals("victim-laptop", detail.endpoint?.hostname)
        assertEquals("URL_BLOCK", detail.processing?.mitigationAction)
        assertEquals(92.5, detail.processing?.riskAssessment?.riskScore ?: 0.0, 0.01)
        assertEquals("HIGH", detail.processing?.riskAssessment?.riskLevel)

        val detectors = detail.processing?.detectorResults ?: emptyList()
        assertEquals(1, detectors.size)
        assertEquals("detect_phishing", detectors[0].detectorId)
        assertTrue(detectors[0].detected)
        assertEquals(0.95, detectors[0].confidence, 0.01)
        assertEquals(1, detectors[0].evidence.size)
        assertEquals("PHISH_URL", detectors[0].evidence[0].code)
    }

    // 4. Event ID Deduplication & First-Load Suppression
    @Test
    fun testEventIdDeduplicationAndFirstSync() {
        val initialList = listOf(
            ThreatSummary(id = "evt-001", attackType = "SQL_INJECTION", severity = "HIGH", riskScore = 90.0),
            ThreatSummary(id = "evt-002", attackType = "BOLA", severity = "HIGH", riskScore = 85.0)
        )

        // First sync: suppresses notifications to avoid spamming older history
        val notifiedFirst = ThreatMonitor.processIncomingThreats(initialList)
        assertTrue("First sync must suppress historical notifications", notifiedFirst.isEmpty())
        assertEquals(2, ThreatMonitor.getSeenCount())
        assertTrue(ThreatMonitor.isSeen("evt-001"))
        assertTrue(ThreatMonitor.isSeen("evt-002"))

        // Second poll with SAME events: deduplication must prevent duplicate alerts
        val notifiedSecond = ThreatMonitor.processIncomingThreats(initialList)
        assertTrue("Subsequent poll with same events must not notify", notifiedSecond.isEmpty())
        assertEquals(2, ThreatMonitor.getSeenCount())

        // Third poll with ONE genuinely NEW event: must trigger notification for only the new event
        val updatedList = initialList + ThreatSummary(
            id = "evt-003-new-laptop-threat",
            attackType = "SUSPICIOUS_PROCESS_EXECUTION",
            severity = "CRITICAL",
            riskScore = 98.0
        )
        val notifiedThird = ThreatMonitor.processIncomingThreats(updatedList)
        assertEquals(1, notifiedThird.size)
        assertEquals("evt-003-new-laptop-threat", notifiedThird[0].id)
        assertEquals(3, ThreatMonitor.getSeenCount())
        assertTrue(ThreatMonitor.isSeen("evt-003-new-laptop-threat"))

        // Fourth poll with another duplicate: no notification
        val notifiedFourth = ThreatMonitor.processIncomingThreats(updatedList)
        assertTrue(notifiedFourth.isEmpty())
    }

    // 5. Empty Incident List Handling
    @Test
    fun testEmptyIncidentListHandling() {
        val notified = ThreatMonitor.processIncomingThreats(emptyList())
        assertTrue(notified.isEmpty())
        assertEquals(0, ThreatMonitor.getSeenCount())
    }

    // 6. Malformed JSON Handling
    @Test
    fun testMalformedJsonHandling() {
        val malformedJson = "{ broken json content: invalid }"
        var exceptionThrown = false
        try {
            json.decodeFromString(ThreatDetail.serializer(), malformedJson)
        } catch (e: SerializationException) {
            exceptionThrown = true
        }
        assertTrue("Malformed JSON must throw SerializationException", exceptionThrown)
    }

    // 7. Unknown Fields Graceful Tolerance (Backward & Forward Compatibility)
    @Test
    fun testUnknownFieldsToleratedGracefully() {
        val jsonWithExtraFields = """
        {
            "id": "evt-future-100",
            "attackType": "SSRF",
            "severity": "HIGH",
            "riskScore": 89.0,
            "futureFieldUnknownToApp": "future_value",
            "extraNested": {"random": 123}
        }
        """.trimIndent()

        val item = json.decodeFromString(ThreatSummary.serializer(), jsonWithExtraFields)
        assertEquals("evt-future-100", item.id)
        assertEquals("SSRF", item.attackType)
        assertEquals(89.0, item.riskScore, 0.01)
    }
}

