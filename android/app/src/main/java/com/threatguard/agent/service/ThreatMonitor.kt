package com.threatguard.agent.service

import android.content.Context
import com.threatguard.agent.api.ApiClient
import com.threatguard.agent.model.ThreatSummary
import com.threatguard.agent.notification.ThreatNotificationManager
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

object ThreatMonitor {

    private val seenEventIds = mutableSetOf<String>()
    private val _incidents = MutableStateFlow<List<ThreatSummary>>(emptyList())
    val incidents: StateFlow<List<ThreatSummary>> = _incidents.asStateFlow()

    private val _isPolling = MutableStateFlow(false)
    val isPolling: StateFlow<Boolean> = _isPolling.asStateFlow()

    private val _lastPollStatus = MutableStateFlow<String>("Initialized")
    val lastPollStatus: StateFlow<String> = _lastPollStatus.asStateFlow()

    private var monitorJob: Job? = null
    private var isFirstSync = true

    fun startPolling(context: Context, intervalMs: Long = 6000L) {
        if (monitorJob?.isActive == true) return

        _isPolling.value = true
        monitorJob = CoroutineScope(Dispatchers.IO).launch {
            while (isActive) {
                try {
                    val api = ApiClient.getInstance(context)
                    val result = api.getThreats()

                    result.onSuccess { threatList ->
                        _incidents.value = threatList
                        _lastPollStatus.value = "Connected: ${threatList.size} incidents recorded"

                        val newThreats = threatList.filter { it.id !in seenEventIds }

                        if (isFirstSync) {
                            // On first load, record existing IDs into cache so we don't spam notifications for older history
                            threatList.forEach { seenEventIds.add(it.id) }
                            isFirstSync = false
                        } else {
                            // On subsequent polls, trigger notification for genuine NEW threats
                            for (threat in newThreats) {
                                seenEventIds.add(threat.id)
                                if (ThreatNotificationManager.shouldNotifyForThreat(threat)) {
                                    withContext(Dispatchers.Main) {
                                        ThreatNotificationManager.showThreatNotification(context, threat)
                                    }
                                }
                            }
                        }
                    }.onFailure { err ->
                        _lastPollStatus.value = "Poll error: ${err.message}"
                    }
                } catch (e: Exception) {
                    _lastPollStatus.value = "Poll exception: ${e.message}"
                }
                delay(intervalMs)
            }
        }
    }

    fun stopPolling() {
        monitorJob?.cancel()
        monitorJob = null
        _isPolling.value = false
    }

    fun markSeen(eventId: String) {
        seenEventIds.add(eventId)
    }

    fun isSeen(eventId: String): Boolean = eventId in seenEventIds

    fun getSeenCount(): Int = seenEventIds.size

    fun getSeenEventIds(): Set<String> = seenEventIds.toSet()

    fun resetState() {
        seenEventIds.clear()
        _incidents.value = emptyList()
        _lastPollStatus.value = "Initialized"
        isFirstSync = true
    }

    /**
     * Testable core logic for evaluating incoming threats, deduplication, and notification dispatch.
     * Returns the list of newly detected threats that qualified for notification.
     */
    fun processIncomingThreats(
        threatList: List<ThreatSummary>,
        onNotify: (ThreatSummary) -> Unit = {}
    ): List<ThreatSummary> {
        _incidents.value = threatList
        val newThreats = threatList.filter { it.id !in seenEventIds }
        val notified = mutableListOf<ThreatSummary>()

        if (isFirstSync) {
            threatList.forEach { seenEventIds.add(it.id) }
            isFirstSync = false
        } else {
            for (threat in newThreats) {
                seenEventIds.add(threat.id)
                if (ThreatNotificationManager.shouldNotifyForThreat(threat)) {
                    notified.add(threat)
                    onNotify(threat)
                }
            }
        }
        return notified
    }

    fun getIncidentById(id: String): ThreatSummary? {
        return _incidents.value.firstOrNull { it.id == id }
    }
}

