package com.threatguard.agent.telemetry

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import android.os.Process
import com.threatguard.agent.model.*
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID

data class DeviceSnapshot(
    val model: String,
    val manufacturer: String,
    val androidVersion: String,
    val sdkVersion: Int,
    val networkType: String,
    val batteryLevel: Int,
    val packageName: String,
    val processId: Int
)

class TelemetryCollector(private val context: Context) {

    fun getDeviceSnapshot(): DeviceSnapshot {
        val batteryManager = context.getSystemService(Context.BATTERY_SERVICE) as? BatteryManager
        val batteryLevel = batteryManager?.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY) ?: -1

        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val activeNetwork = connectivityManager?.activeNetwork
        val caps = connectivityManager?.getNetworkCapabilities(activeNetwork)
        val networkType = when {
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "Wi-Fi"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "Cellular"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> "Ethernet"
            else -> "Unknown / Disconnected"
        }

        return DeviceSnapshot(
            model = Build.MODEL ?: "Generic Android",
            manufacturer = Build.MANUFACTURER ?: "Android",
            androidVersion = Build.VERSION.RELEASE ?: "Unknown",
            sdkVersion = Build.VERSION.SDK_INT,
            networkType = networkType,
            batteryLevel = batteryLevel,
            packageName = context.packageName,
            processId = Process.myPid()
        )
    }

    fun buildHealthyTelemetryEvent(): ApiSecurityEvent {
        val snapshot = getDeviceSnapshot()
        val isoFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        val timestamp = isoFormat.format(Date())
        val eventId = "evt-android-" + UUID.randomUUID().toString()

        val endpointInfo = EndpointInfo(
            eventType = "device_health",
            hostname = "${snapshot.manufacturer}-${snapshot.model}".replace(" ", "-").lowercase(),
            username = "android_user",
            processName = snapshot.packageName,
            processId = snapshot.processId,
            parentProcess = "zygote",
            executablePath = "/data/app/${snapshot.packageName}/base.apk",
            commandLine = snapshot.packageName,
            privilegeLevel = "USER",
            keyboardHook = false,
            networkConnection = false,
            elevated = false
        )

        val networkInfo = NetworkInfo(
            sourceIp = "192.168.1.55",
            userAgent = "ThreatGuard-Android/1.0 (${snapshot.manufacturer}; ${snapshot.model}; Android ${snapshot.androidVersion})",
            destinationIp = "10.0.2.2",
            sourcePort = 42100,
            destinationPort = 8000,
            protocol = "TCP",
            bytes = 380,
            packets = 3,
            connectionStatus = "success"
        )

        val requestInfo = RequestInfo(
            method = "POST",
            endpoint = "/api/mobile/telemetry",
            headers = mapOf(
                "X-Device-Model" to snapshot.model,
                "X-OS-Version" to snapshot.androidVersion,
                "X-Network-Type" to snapshot.networkType
            )
        )

        return ApiSecurityEvent(
            eventId = eventId,
            timestamp = timestamp,
            domain = "ENDPOINT",
            network = networkInfo,
            endpoint = endpointInfo,
            request = requestInfo,
            resource = ResourceInfo(
                resourceType = "mobile_endpoint",
                resourceId = snapshot.model,
                ownerId = "android_user"
            )
        )
    }
}
