package com.threatguard.agent

import com.threatguard.agent.model.*
import com.threatguard.agent.simulation.LabScenario
import com.threatguard.agent.simulation.ScenarioSimulator
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.*
import org.junit.Test

class ApiSecurityEventTest {

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        isLenient = true
    }

    @Test
    fun testSerializationProducesValidBackendStructure() {
        val scenarioEvent = ScenarioSimulator.buildEventForScenario(LabScenario.SUSPICIOUS_APP)
        val serialized = json.encodeToString(ApiSecurityEvent.serializer(), scenarioEvent)

        assertTrue(serialized.contains("\"schema_version\":\"1.0\""))
        assertTrue(serialized.contains("\"domain\":\"ENDPOINT\""))
        assertTrue(serialized.contains("\"event_id\":"))
        assertTrue(serialized.contains("\"endpoint\":"))
        assertTrue(serialized.contains("\"suspicious_process_execution\""))
        assertTrue(serialized.contains("\"powershell.exe -EncodedCommand SYNTHETIC_DEMO\""))
    }

    @Test
    fun testAllScenariosProduceNonNullValidEvents() {
        for (scenario in LabScenario.values()) {
            val event = ScenarioSimulator.buildEventForScenario(scenario)
            assertNotNull("Event for scenario $scenario must not be null", event)
            assertTrue("Event ID must be populated", event.eventId.startsWith("evt-sim-"))
            assertNotNull("Network must be populated", event.network)
            assertNotNull("Request endpoint must be present", event.request.endpoint)
        }
    }

    @Test
    fun testFakeBankingUrlScenarioMatchesPhishingPath() {
        val event = ScenarioSimulator.buildEventForScenario(LabScenario.FAKE_BANKING_URL)
        assertEquals("/lab/phishing/login", event.request.endpoint)
        assertEquals("fake_bank", event.endpoint?.eventType)
    }

    @Test
    fun testProcessingResultDeserialization() {
        val rawJson = """
        {
            "event_id": "evt-test-123",
            "source_ip": "192.168.1.50",
            "status": "processed",
            "message": "Event processed successfully",
            "mitigation_action": "QUARANTINE",
            "risk_assessment": {
                "risk_score": 85.5,
                "risk_level": "HIGH",
                "threat_detected": true,
                "attack_types": ["SUSPICIOUS_PROCESS_EXECUTION"],
                "reasons": ["Suspicious process execution detected"]
            },
            "impact": {
                "impact_identified": true,
                "primary_impact": "endpoint compromise",
                "categories": ["endpoint compromise"],
                "severity": "CRITICAL"
            },
            "ai_analysis": {
                "threat_explanation": "Suspicious execution detected.",
                "confidence_level": "CONFIRMED"
            }
        }
        """.trimIndent()

        val parsed = json.decodeFromString(ProcessingResult.serializer(), rawJson)
        assertEquals("evt-test-123", parsed.eventId)
        assertEquals("QUARANTINE", parsed.mitigationAction)
        assertEquals(true, parsed.riskAssessment?.threatDetected)
        assertEquals(85.5, parsed.riskAssessment?.riskScore ?: 0.0, 0.01)
        assertEquals("endpoint compromise", parsed.impact?.primaryImpact)

        val aiObj = parsed.aiAnalysis?.jsonObject
        assertEquals("CONFIRMED", aiObj?.get("confidence_level")?.jsonPrimitive?.content)
    }
}
