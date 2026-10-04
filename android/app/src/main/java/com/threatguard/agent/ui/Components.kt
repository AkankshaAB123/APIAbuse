package com.threatguard.agent.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.threatguard.agent.model.ProcessingResult
import com.threatguard.agent.ui.theme.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive

@Composable
fun ResultCard(result: ProcessingResult) {
    val risk = result.riskAssessment
    val impact = result.impact
    val ai = result.aiAnalysis

    val severityColor = when (risk?.riskLevel?.uppercase()) {
        "CRITICAL" -> DangerRed
        "HIGH" -> DangerRed
        "MEDIUM" -> WarningAmber
        "LOW" -> NeonGreen
        else -> NeonCyan
    }

    val actionColor = when (result.mitigationAction.uppercase()) {
        "QUARANTINE", "BLOCK", "URL_BLOCK", "TRANSACTION_BLOCK" -> DangerRed
        "RATE_LIMIT", "MONITOR" -> WarningAmber
        else -> NeonGreen
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, severityColor.copy(alpha = 0.6f), RoundedCornerShape(12.dp)),
        colors = CardDefaults.cardColors(containerColor = CyberSurfaceVariant),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = if (risk?.threatDetected == true) "?? THREAT DETECTED" else "? CLEAN TELEMETRY",
                    color = severityColor,
                    fontWeight = FontWeight.Bold,
                    fontSize = 18.sp
                )
                Surface(
                    color = actionColor.copy(alpha = 0.2f),
                    shape = RoundedCornerShape(6.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, actionColor)
                ) {
                    Text(
                        text = result.mitigationAction,
                        color = actionColor,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                        fontWeight = FontWeight.Bold,
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))
            HorizontalDivider(color = CyberSurface)
            Spacer(modifier = Modifier.height(12.dp))

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Column {
                    Text("Risk Score", color = TextSecondary, fontSize = 12.sp)
                    Text("${risk?.riskScore?.toInt() ?: 0}/100", color = severityColor, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                }
                Column {
                    Text("Severity", color = TextSecondary, fontSize = 12.sp)
                    Text(risk?.riskLevel ?: "UNKNOWN", color = severityColor, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                }
                Column {
                    Text("Primary Impact", color = TextSecondary, fontSize = 12.sp)
                    Text(impact?.primaryImpact ?: "None", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                }
            }

            if (!risk?.attackTypes.isNullOrEmpty()) {
                Spacer(modifier = Modifier.height(10.dp))
                Text("Identified Attack: ${risk?.attackTypes?.joinToString(", ")}", color = NeonCyan, fontSize = 13.sp)
            }

            if (!impact?.reasons.isNullOrEmpty()) {
                Spacer(modifier = Modifier.height(6.dp))
                Text("Impact Details: ${impact?.reasons?.firstOrNull() ?: ""}", color = TextSecondary, fontSize = 12.sp)
            }

            if (ai is JsonObject) {
                val explanation = ai["threat_explanation"]?.jsonPrimitive?.content
                val conf = ai["confidence_level"]?.jsonPrimitive?.content ?: "UNKNOWN"

                Spacer(modifier = Modifier.height(12.dp))
                Surface(
                    color = CyberNavy.copy(alpha = 0.8f),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                            Text("?? AI Reasoning (Gemini + RAG)", color = NeonCyan, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                            Text("Confidence: $conf", color = if (conf == "CONFIRMED") NeonGreen else WarningAmber, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                        }
                        if (!explanation.isNullOrBlank()) {
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(explanation, color = TextPrimary, fontSize = 12.sp, lineHeight = 16.sp)
                        }
                    }
                }
            }
        }
    }
}
