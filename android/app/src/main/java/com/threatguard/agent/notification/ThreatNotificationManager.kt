package com.threatguard.agent.notification

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.threatguard.agent.MainActivity
import com.threatguard.agent.model.ThreatSummary

object ThreatNotificationManager {

    const val CHANNEL_ID = "threatguard_security_alerts"
    private const val CHANNEL_NAME = "Security Incident Alerts"
    private const val CHANNEL_DESC = "Notifications for HIGH and CRITICAL security incidents detected on your protected devices."

    fun createNotificationChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val importance = NotificationManager.IMPORTANCE_HIGH
            val channel = NotificationChannel(CHANNEL_ID, CHANNEL_NAME, importance).apply {
                description = CHANNEL_DESC
                enableLights(true)
                enableVibration(true)
            }
            val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
        }
    }

    fun hasNotificationPermission(context: Context): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(
                context,
                android.Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            true
        }
    }

    fun shouldNotifyForThreat(threat: ThreatSummary): Boolean {
        val sev = threat.severity?.uppercase() ?: "LOW"
        val riskScore = threat.riskScore
        return (sev == "HIGH" || sev == "CRITICAL" || riskScore >= 75.0)
    }

    fun showThreatNotification(context: Context, threat: ThreatSummary) {
        if (!shouldNotifyForThreat(threat)) {
            return
        }
        if (!hasNotificationPermission(context)) {
            return
        }

        createNotificationChannel(context)

        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("EXTRA_INCIDENT_ID", threat.id)
        }

        val pendingIntent = PendingIntent.getActivity(
            context,
            threat.id.hashCode(),
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val deviceName = when {
            threat.endpoint?.contains("laptop", ignoreCase = true) == true -> "Protected Laptop"
            threat.sourceIp != null && threat.sourceIp != "127.0.0.1" -> "Device (${threat.sourceIp})"
            else -> "Host / Laptop"
        }

        val actionText = threat.action.ifBlank { "MONITOR" }
        val attackName = threat.attackType.replace("_", " ")
        val scoreFormatted = String.format(java.util.Locale.US, "%.1f", threat.riskScore)
        val title = "THREATGUARD SECURITY ALERT"
        val content = "$attackName | Risk: ${threat.severity ?: "HIGH"} ($scoreFormatted) | Action: $actionText"

        val builder = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(title)
            .setContentText(content)
            .setStyle(NotificationCompat.BigTextStyle().bigText(
                "ThreatGuard Security Alert\n" +
                "Threat: $attackName\n" +
                "Host: $deviceName\n" +
                "Risk: ${threat.severity ?: "HIGH"} ($scoreFormatted)\n" +
                "Action Enforced: $actionText\n\n" +
                "Tap to review incident details and AI analysis."
            ))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)

        try {
            val manager = NotificationManagerCompat.from(context)
            manager.notify(threat.id.hashCode(), builder.build())
        } catch (e: SecurityException) {
            // Gracefully ignore if user revoked permission
        }
    }
}
