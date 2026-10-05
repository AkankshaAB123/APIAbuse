package com.threatguard.agent

import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.threatguard.agent.model.ProcessingResult
import com.threatguard.agent.notification.ThreatNotificationManager
import com.threatguard.agent.service.ThreatMonitor
import com.threatguard.agent.ui.*
import com.threatguard.agent.ui.theme.*

enum class AppDestination(val label: String, val icon: ImageVector) {
    HOME("Security", Icons.Default.Shield),
    INCIDENTS("Incidents", Icons.Default.Warning),
    LAB("Lab", Icons.Default.Science),
    HISTORY("History", Icons.Default.History),
    SETTINGS("Settings", Icons.Default.Settings)
}

class MainActivity : ComponentActivity() {

    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ -> }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Request runtime notification permission on Android 13+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (!ThreatNotificationManager.hasNotificationPermission(this)) {
                requestPermissionLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        // Start background polling while app is active
        ThreatMonitor.startPolling(this, intervalMs = 5000L)

        val incidentIdFromNotification = intent?.getStringExtra("EXTRA_INCIDENT_ID")

        setContent {
            ThreatGuardTheme {
                ThreatGuardApp(initialIncidentId = incidentIdFromNotification)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        ThreatMonitor.startPolling(this, intervalMs = 5000L)
    }

    override fun onPause() {
        super.onPause()
        ThreatMonitor.stopPolling()
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ThreatGuardApp(initialIncidentId: String? = null) {
    var currentDestination by remember { mutableStateOf(if (initialIncidentId != null) AppDestination.INCIDENTS else AppDestination.HOME) }
    var selectedIncidentId by remember { mutableStateOf<String?>(initialIncidentId) }
    var lastResult by remember { mutableStateOf<ProcessingResult?>(null) }
    val historyList = remember { mutableStateListOf<Pair<String, ProcessingResult>>() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                        Text(
                            text = "THREATGUARD",
                            fontWeight = FontWeight.Black,
                            fontSize = 18.sp,
                            color = NeonCyan,
                            letterSpacing = 1.sp
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "COMPANION",
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp,
                            color = NeonGreen
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = CyberSurface
                )
            )
        },
        bottomBar = {
            NavigationBar(
                containerColor = CyberSurface
            ) {
                AppDestination.values().forEach { destination ->
                    NavigationBarItem(
                        selected = currentDestination == destination && selectedIncidentId == null,
                        onClick = {
                            selectedIncidentId = null
                            currentDestination = destination
                        },
                        icon = { Icon(destination.icon, contentDescription = destination.label) },
                        label = { Text(destination.label, fontSize = 10.sp) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = NeonCyan,
                            selectedTextColor = NeonCyan,
                            unselectedIconColor = TextSecondary,
                            unselectedTextColor = TextSecondary,
                            indicatorColor = CyberSurfaceVariant
                        )
                    )
                }
            }
        },
        containerColor = CyberNavy
    ) { innerPadding ->
        Box(modifier = Modifier.padding(innerPadding)) {
            if (selectedIncidentId != null) {
                IncidentDetailScreen(
                    eventId = selectedIncidentId!!,
                    onBack = { selectedIncidentId = null }
                )
            } else {
                when (currentDestination) {
                    AppDestination.HOME -> HomeScreen(
                        onNavigateToLab = { currentDestination = AppDestination.LAB },
                        onNavigateToIncidents = { currentDestination = AppDestination.INCIDENTS },
                        onSelectIncident = { selectedIncidentId = it },
                        onResultGenerated = { lastResult = it },
                        lastResult = lastResult
                    )
                    AppDestination.INCIDENTS -> RealIncidentsListScreen(
                        onSelectIncident = { selectedIncidentId = it }
                    )
                    AppDestination.LAB -> LabScreen(
                        onResultGenerated = { lastResult = it },
                        onScenarioRan = { title, result ->
                            historyList.add(Pair(title, result))
                        }
                    )
                    AppDestination.HISTORY -> HistoryScreen(history = historyList)
                    AppDestination.SETTINGS -> SettingsScreen()
                }
            }
        }
    }
}
