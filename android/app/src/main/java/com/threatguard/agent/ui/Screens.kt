package com.threatguard.agent.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.threatguard.agent.api.ApiClient
import com.threatguard.agent.model.ProcessingResult
import com.threatguard.agent.model.ThreatDetail
import com.threatguard.agent.model.ThreatSummary
import com.threatguard.agent.service.ThreatMonitor
import com.threatguard.agent.simulation.LabScenario
import com.threatguard.agent.simulation.ScenarioSimulator
import com.threatguard.agent.telemetry.TelemetryCollector
import com.threatguard.agent.ui.theme.*
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive

@Composable
fun HomeScreen(
    onNavigateToLab: () -> Unit,
    onNavigateToIncidents: () -> Unit,
    onSelectIncident: (String) -> Unit,
    onResultGenerated: (ProcessingResult) -> Unit,
    lastResult: ProcessingResult?
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val telemetryCollector = remember { TelemetryCollector(context) }
    val snapshot = remember { telemetryCollector.getDeviceSnapshot() }
    var isTransmitting by remember { mutableStateOf(false) }
    var statusMessage by remember { mutableStateOf<String?>(null) }

    val recentBackendIncidents by ThreatMonitor.incidents.collectAsState()
    val backendStatus by ThreatMonitor.lastPollStatus.collectAsState()

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = CyberSurfaceVariant),
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(1.dp, NeonCyan.copy(alpha = 0.3f), RoundedCornerShape(14.dp))
            ) {
                Column(modifier = Modifier.padding(18.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("DEVICE POSTURE & COMPANION", color = NeonCyan, fontSize = 12.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
                        Surface(
                            color = if (backendStatus.startsWith("Connected")) NeonGreen.copy(alpha = 0.2f) else WarningAmber.copy(alpha = 0.2f),
                            shape = RoundedCornerShape(6.dp)
                        ) {
                            Text(
                                text = if (backendStatus.startsWith("Connected")) "ONLINE" else "DISCONNECTED",
                                color = if (backendStatus.startsWith("Connected")) NeonGreen else WarningAmber,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = if (lastResult?.riskAssessment?.threatDetected == true) "ATTENTION REQUIRED" else "DEVICE MONITORED & ACTIVE",
                        color = if (lastResult?.riskAssessment?.threatDetected == true) DangerRed else NeonGreen,
                        fontSize = 20.sp,
                        fontWeight = FontWeight.ExtraBold
                    )
                    Spacer(modifier = Modifier.height(14.dp))
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Column {
                            Text("Device", color = TextSecondary, fontSize = 11.sp)
                            Text("${snapshot.manufacturer} ${snapshot.model}", color = TextPrimary, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                        }
                        Column {
                            Text("Android Version", color = TextSecondary, fontSize = 11.sp)
                            Text("Android ${snapshot.androidVersion} (API ${snapshot.sdkVersion})", color = TextPrimary, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                        }
                    }
                    Spacer(modifier = Modifier.height(10.dp))
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Column {
                            Text("Network State", color = TextSecondary, fontSize = 11.sp)
                            Text(snapshot.networkType, color = NeonCyan, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                        }
                        Column {
                            Text("Real-Time Telemetry", color = TextSecondary, fontSize = 11.sp)
                            Text("${recentBackendIncidents.size} incidents synced", color = TextPrimary, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                        }
                    }
                }
            }
        }

        item {
            Button(
                onClick = {
                    scope.launch {
                        isTransmitting = true
                        statusMessage = "Transmitting device telemetry to /events..."
                        val event = telemetryCollector.buildHealthyTelemetryEvent()
                        val api = ApiClient.getInstance(context)
                        val res = api.postEvent(event)
                        isTransmitting = false
                        res.onSuccess {
                            onResultGenerated(it)
                            statusMessage = "Telemetry verified: ${it.mitigationAction}"
                        }.onFailure {
                            statusMessage = "Transmission error: ${it.message}"
                        }
                    }
                },
                enabled = !isTransmitting,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = NeonCyan, contentColor = Color.Black),
                shape = RoundedCornerShape(10.dp)
            ) {
                Icon(Icons.Default.Send, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(if (isTransmitting) "Evaluating..." else "Send Safe Device Telemetry", fontWeight = FontWeight.Bold)
            }
            if (statusMessage != null) {
                Spacer(modifier = Modifier.height(4.dp))
                Text(statusMessage!!, color = TextSecondary, fontSize = 12.sp, modifier = Modifier.padding(start = 4.dp))
            }
        }

        if (recentBackendIncidents.isNotEmpty()) {
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("REAL LAPTOP / HOST INCIDENTS", color = NeonCyan, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    TextButton(onClick = { onNavigateToIncidents() }) {
                        Text("View All (${recentBackendIncidents.size})", color = NeonCyan, fontSize = 12.sp)
                    }
                }
                val latest = recentBackendIncidents.first()
                IncidentSummaryCard(threat = latest, onClick = { onSelectIncident(latest.id) })
            }
        }

        if (lastResult != null) {
            item {
                Text("LATEST VERIFIED PIPELINE RESULT", color = TextSecondary, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                Spacer(modifier = Modifier.height(6.dp))
                ResultCard(lastResult)
            }
        }

        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = CyberSurface),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onNavigateToLab() }
                    .border(1.dp, CyberSurfaceVariant, RoundedCornerShape(12.dp))
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Default.Science, contentDescription = null, tint = NeonCyan, modifier = Modifier.size(28.dp))
                    Spacer(modifier = Modifier.width(14.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Controlled Security Lab", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                        Text("Simulate 6 safe attack scenarios to test the ML, Risk, and RAG pipeline.", color = TextSecondary, fontSize = 12.sp)
                    }
                    Icon(Icons.Default.ChevronRight, contentDescription = null, tint = TextSecondary)
                }
            }
        }
    }
}

@Composable
fun IncidentSummaryCard(threat: ThreatSummary, onClick: () -> Unit) {
    val sevColor = when (threat.severity?.uppercase()) {
        "CRITICAL", "HIGH" -> DangerRed
        "MEDIUM" -> WarningAmber
        else -> NeonGreen
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() }
            .border(1.dp, sevColor.copy(alpha = 0.5f), RoundedCornerShape(12.dp)),
        colors = CardDefaults.cardColors(containerColor = CyberSurfaceVariant),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Computer, contentDescription = null, tint = NeonCyan, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = if (threat.endpoint?.contains("laptop", ignoreCase = true) == true) "User Laptop" else "Protected Host",
                        color = TextPrimary,
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                }
                Surface(
                    color = sevColor.copy(alpha = 0.2f),
                    shape = RoundedCornerShape(4.dp)
                ) {
                    Text(
                        text = "${threat.severity ?: "UNKNOWN"} (${threat.riskScore.toInt()})",
                        color = sevColor,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))
            Text(threat.attackType, color = NeonCyan, fontSize = 15.sp, fontWeight = FontWeight.Bold)

            Spacer(modifier = Modifier.height(6.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text("Action: ${threat.action}", color = TextSecondary, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                Text(threat.sourceIp ?: "127.0.0.1", color = TextSecondary, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
            }
        }
    }
}

@Composable
fun IncidentDetailScreen(eventId: String, onBack: () -> Unit) {
    val context = LocalContext.current
    var detail by remember { mutableStateOf<ThreatDetail?>(null) }
    var isLoading by remember { mutableStateOf(true) }
    var errorMsg by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(eventId) {
        isLoading = true
        val api = ApiClient.getInstance(context)
        val res = api.getThreatDetail(eventId)
        isLoading = false
        res.onSuccess {
            detail = it
        }.onFailure {
            errorMsg = it.message
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(CyberNavy)
            .padding(16.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) {
                Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = NeonCyan)
            }
            Spacer(modifier = Modifier.width(8.dp))
            Text("INCIDENT DETAILS", color = NeonCyan, fontSize = 16.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
        }

        Spacer(modifier = Modifier.height(14.dp))

        if (isLoading) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = NeonCyan)
            }
        } else if (errorMsg != null) {
            Text("Failed to retrieve incident: $errorMsg", color = DangerRed)
        } else if (detail != null) {
            val d = detail!!
            val proc = d.processing
            val risk = proc?.riskAssessment
            val impact = proc?.impact ?: d.impact
            val ai = proc?.aiAnalysis

            val sevColor = when (risk?.riskLevel?.uppercase()) {
                "CRITICAL", "HIGH" -> DangerRed
                "MEDIUM" -> WarningAmber
                else -> NeonGreen
            }

            val detectors = proc?.detectorResults ?: emptyList()
            val detectedDetectors = detectors.filter { it.detected }

            LazyColumn(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                item {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = CyberSurfaceVariant),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth().border(1.dp, sevColor, RoundedCornerShape(12.dp))
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text("VERIFIED INCIDENT", color = sevColor, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                                Text(d.timestamp ?: "Unknown Time", color = TextSecondary, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                            }
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(risk?.attackTypes?.firstOrNull() ?: "Detected Threat", color = TextPrimary, fontSize = 20.sp, fontWeight = FontWeight.ExtraBold)
                            Spacer(modifier = Modifier.height(10.dp))
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                Column {
                                    Text("Risk Score", color = TextSecondary, fontSize = 12.sp)
                                    Text("${risk?.riskScore?.toInt() ?: 0} / 100", color = sevColor, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                                }
                                Column {
                                    Text("Severity", color = TextSecondary, fontSize = 12.sp)
                                    Text(risk?.riskLevel ?: "UNKNOWN", color = sevColor, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                                }
                                Column {
                                    Text("Mitigation", color = TextSecondary, fontSize = 12.sp)
                                    Text(proc?.mitigationAction ?: "ALLOW", color = NeonCyan, fontWeight = FontWeight.Bold, fontSize = 16.sp, fontFamily = FontFamily.Monospace)
                                }
                            }
                        }
                    }
                }

                item {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = CyberSurface),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Text("DEVICE, DOMAIN & ORIGIN", color = NeonCyan, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                            Spacer(modifier = Modifier.height(8.dp))
                            Text("Event ID: ${d.eventId}", color = NeonCyan, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                            Text("Domain: ${d.domain}", color = TextPrimary, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                            Text("Device Hostname: ${d.endpoint?.hostname ?: "User Laptop / Host"}", color = TextPrimary, fontSize = 13.sp)
                            Text("Process: ${d.endpoint?.processName ?: "N/A"}", color = TextSecondary, fontSize = 13.sp)
                            Text("Target Endpoint: ${d.request?.endpoint ?: "/events"}", color = TextSecondary, fontSize = 13.sp)
                            Text("Source IP: ${d.network?.sourceIp ?: "127.0.0.1"}", color = TextSecondary, fontSize = 13.sp)
                            if (d.timestamp != null) {
                                Text("Timestamp: ${d.timestamp}", color = TextSecondary, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                            }
                        }
                    }
                }

                if (detectedDetectors.isNotEmpty()) {
                    item {
                        Card(
                            colors = CardDefaults.cardColors(containerColor = CyberSurface),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(14.dp)) {
                                Text("DETECTION SOURCE & EVIDENCE", color = NeonCyan, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                                Spacer(modifier = Modifier.height(8.dp))
                                detectedDetectors.forEach { det ->
                                    Column(modifier = Modifier.padding(vertical = 4.dp)) {
                                        Row(
                                            modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.SpaceBetween
                                        ) {
                                            Text(det.detectorId, color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                                            Text("Conf: ${(det.confidence * 100).toInt()}%", color = NeonGreen, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                                        }
                                        Text("Source: ${det.source} | Domain: ${det.domain} | Sev: ${det.severity}", color = TextSecondary, fontSize = 11.sp)
                                        det.evidence.forEach { ev ->
                                            Text("• [${ev.code}] ${ev.message}", color = WarningAmber, fontSize = 11.sp)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                item {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = CyberSurface),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Text("CONCRETE IMPACT ASSESSMENT", color = WarningAmber, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                            Spacer(modifier = Modifier.height(8.dp))
                            Text("Primary Impact: ${impact?.primaryImpact ?: "None"}", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                            if (!impact?.categories.isNullOrEmpty()) {
                                Text("Categories: ${impact?.categories?.joinToString(", ") ?: ""}", color = TextSecondary, fontSize = 12.sp)
                            }
                            if (!impact?.reasons.isNullOrEmpty()) {
                                Spacer(modifier = Modifier.height(4.dp))
                                Text("Reasoning: ${impact?.reasons?.joinToString("; ") ?: ""}", color = TextSecondary, fontSize = 12.sp)
                            }
                        }
                    }
                }

                if (ai is JsonObject) {
                    val explanation = ai["threat_explanation"]?.jsonPrimitive?.content
                    val conf = ai["confidence_level"]?.jsonPrimitive?.content ?: "UNKNOWN"
                    val evidenceText = ai["evidence"]?.jsonPrimitive?.content
                    val recAction = ai["recommended_action"]?.jsonPrimitive?.content

                    item {
                        Card(
                            colors = CardDefaults.cardColors(containerColor = CyberSurfaceVariant),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.fillMaxWidth().border(1.dp, NeonCyan.copy(alpha = 0.4f), RoundedCornerShape(12.dp))
                        ) {
                            Column(modifier = Modifier.padding(14.dp)) {
                                Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                                    Text("RAG + GEMINI EXPLANATION", color = NeonCyan, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                                    Text("CONFIDENCE: $conf", color = NeonGreen, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                }
                                if (!explanation.isNullOrBlank()) {
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Text(explanation, color = TextPrimary, fontSize = 13.sp, lineHeight = 18.sp)
                                }
                                if (!evidenceText.isNullOrBlank()) {
                                    Spacer(modifier = Modifier.height(6.dp))
                                    Text("Evidence: $evidenceText", color = WarningAmber, fontSize = 12.sp)
                                }
                                if (!recAction.isNullOrBlank()) {
                                    Spacer(modifier = Modifier.height(6.dp))
                                    Text("Recommended Action: $recAction", color = NeonCyan, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun RealIncidentsListScreen(onSelectIncident: (String) -> Unit) {
    val incidents by ThreatMonitor.incidents.collectAsState()
    val isPolling by ThreatMonitor.isPolling.collectAsState()

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("ACTIVE HOST THREAT INCIDENTS", color = NeonCyan, fontSize = 12.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
            if (isPolling) {
                Text("?? LIVE MONITORING", color = DangerRed, fontSize = 10.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        if (incidents.isEmpty()) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("No incidents recorded by backend.", color = TextSecondary, fontSize = 14.sp)
            }
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                items(incidents) { threat ->
                    IncidentSummaryCard(threat = threat, onClick = { onSelectIncident(threat.id) })
                }
            }
        }
    }
}

@Composable
fun LabScreen(
    onResultGenerated: (ProcessingResult) -> Unit,
    onScenarioRan: (String, ProcessingResult) -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var runningScenario by remember { mutableStateOf<LabScenario?>(null) }
    var activeResult by remember { mutableStateOf<ProcessingResult?>(null) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Text("CONTROLLED SECURITY LAB", color = NeonCyan, fontSize = 12.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
            Text("Simulate synthetic client-side attack scenarios. Telemetry is sent to the existing backend /events endpoint for deterministic detection, ML scoring, and RAG analysis.", color = TextSecondary, fontSize = 13.sp)
        }

        if (errorMessage != null) {
            item {
                Surface(
                    color = DangerRed.copy(alpha = 0.2f),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(errorMessage!!, color = DangerRed, modifier = Modifier.padding(10.dp), fontSize = 13.sp)
                }
            }
        }

        if (activeResult != null) {
            item {
                Text("REAL BACKEND VERIFICATION RESULT", color = NeonGreen, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                Spacer(modifier = Modifier.height(4.dp))
                ResultCard(activeResult!!)
            }
        }

        items(LabScenario.values()) { scenario ->
            Card(
                colors = CardDefaults.cardColors(containerColor = CyberSurfaceVariant),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth().border(1.dp, CyberSurface, RoundedCornerShape(12.dp))
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Surface(color = CyberNavy, shape = RoundedCornerShape(8.dp), modifier = Modifier.size(36.dp)) {
                            Box(contentAlignment = Alignment.Center) {
                                Icon(Icons.Default.Shield, contentDescription = null, tint = NeonCyan, modifier = Modifier.size(20.dp))
                            }
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(scenario.title, color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 15.sp)
                            Text("Expected: ${scenario.expectedMitigation}", color = WarningAmber, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                        }
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(scenario.description, color = TextSecondary, fontSize = 12.sp)
                    Spacer(modifier = Modifier.height(10.dp))
                    Button(
                        onClick = {
                            scope.launch {
                                runningScenario = scenario
                                errorMessage = null
                                val event = ScenarioSimulator.buildEventForScenario(scenario)
                                val api = ApiClient.getInstance(context)
                                val res = api.postEvent(event)
                                runningScenario = null
                                res.onSuccess {
                                    activeResult = it
                                    onResultGenerated(it)
                                    onScenarioRan(scenario.title, it)
                                }.onFailure {
                                    errorMessage = "Simulation request failed: ${it.message}"
                                }
                            }
                        },
                        enabled = runningScenario == null,
                        colors = ButtonDefaults.buttonColors(containerColor = NeonCyan.copy(alpha = 0.2f), contentColor = NeonCyan),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.align(Alignment.End)
                    ) {
                        if (runningScenario == scenario) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), color = NeonCyan, strokeWidth = 2.dp)
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Running Simulation...", fontSize = 12.sp)
                        } else {
                            Text("Run Scenario", fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun HistoryScreen(history: List<Pair<String, ProcessingResult>>) {
    if (history.isEmpty()) {
        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(Icons.Default.History, contentDescription = null, tint = TextSecondary, modifier = Modifier.size(48.dp))
                Spacer(modifier = Modifier.height(8.dp))
                Text("No simulations recorded in this session.", color = TextSecondary, fontSize = 14.sp)
                Text("Run scenarios in the Security Lab to see history.", color = TextSecondary.copy(alpha = 0.7f), fontSize = 12.sp)
            }
        }
    } else {
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            item {
                Text("CLIENT-SIDE SIMULATION HISTORY (${history.size})", color = NeonCyan, fontSize = 12.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
            }
            items(history.reversed()) { (title, result) ->
                Column {
                    Text(title, color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                    Spacer(modifier = Modifier.height(4.dp))
                    ResultCard(result)
                }
            }
        }
    }
}

@Composable
fun SettingsScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var urlText by remember { mutableStateOf(ApiClient.getSavedBaseUrl(context)) }
    var pingResult by remember { mutableStateOf<String?>(null) }
    var isTesting by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text("SETTINGS & CONNECTION", color = NeonCyan, fontSize = 12.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
        Text("Configure the ThreatGuard FastAPI backend address. For Android Emulator, use http://10.0.2.2:8000/. For physical devices, enter your computer's local LAN IP.", color = TextSecondary, fontSize = 13.sp)

        OutlinedTextField(
            value = urlText,
            onValueChange = { urlText = it },
            label = { Text("Backend Base URL") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = NeonCyan,
                unfocusedBorderColor = TextSecondary,
                focusedTextColor = TextPrimary,
                unfocusedTextColor = TextPrimary
            )
        )

        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Button(
                onClick = {
                    ApiClient.saveBaseUrl(context, urlText)
                    pingResult = "Settings saved."
                },
                colors = ButtonDefaults.buttonColors(containerColor = NeonCyan, contentColor = Color.Black),
                shape = RoundedCornerShape(8.dp)
            ) {
                Text("Save URL")
            }

            OutlinedButton(
                onClick = {
                    scope.launch {
                        isTesting = true
                        pingResult = "Testing connection to $urlText..."
                        ApiClient.saveBaseUrl(context, urlText)
                        val api = ApiClient.getInstance(context)
                        val res = api.testConnection()
                        isTesting = false
                        res.onSuccess {
                            pingResult = "? Success: $it"
                        }.onFailure {
                            pingResult = "? Failed: ${it.message}"
                        }
                    }
                },
                enabled = !isTesting,
                shape = RoundedCornerShape(8.dp)
            ) {
                Text(if (isTesting) "Testing..." else "Test Connection")
            }
        }

        if (pingResult != null) {
            Surface(
                color = CyberSurfaceVariant,
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = pingResult!!,
                    color = if (pingResult!!.startsWith("?")) NeonGreen else if (pingResult!!.startsWith("?")) DangerRed else TextPrimary,
                    modifier = Modifier.padding(12.dp),
                    fontSize = 13.sp,
                    fontFamily = FontFamily.Monospace
                )
            }
        }
    }
}
