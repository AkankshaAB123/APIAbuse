package com.threatguard.agent.device

import android.content.Context
import android.os.Build
import java.security.MessageDigest
import java.util.UUID

object DeviceIdentityManager {

    private const val PREFS_NAME = "threatguard_device_identity"
    private const val KEY_DEVICE_ID = "threatguard_device_id"

    /**
     * Return a stable ThreatGuard device ID for this Android device.
     *
     * Invariant:
     * - Generated once and persisted in private SharedPreferences.
     * - Format: ANDROID-<16-HEX-DIGEST> (e.g. ANDROID-A1B2C3D4E5F67890).
     * - Derived from safe, privacy-preserving build parameters (manufacturer, model, board, brand)
     *   plus a fallback random component, ensuring stability without accessing sensitive identifiers
     *   such as IMEI, IMSI, or MAC address.
     */
    fun getDeviceId(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val cached = prefs.getString(KEY_DEVICE_ID, null)
        if (!cached.isNullOrBlank()) {
            return cached
        }

        val raw = buildString {
            append(Build.MANUFACTURER ?: "Android")
            append(Build.MODEL ?: "Generic")
            append(Build.BOARD ?: "Board")
            append(Build.BRAND ?: "Brand")
            append(UUID.randomUUID().toString())
        }

        val digest = MessageDigest.getInstance("SHA-256")
            .digest(raw.toByteArray(Charsets.UTF_8))
            .take(8)
            .joinToString("") { "%02X".format(it) }

        val deviceId = "ANDROID-$digest"

        prefs.edit().putString(KEY_DEVICE_ID, deviceId).apply()
        return deviceId
    }

    /**
     * Compute a deterministic ID from synthetic attributes (useful for unit tests & simulations).
     */
    fun computeDeterministicId(model: String, manufacturer: String, seed: String = "ThreatGuard"): String {
        val raw = "$manufacturer-$model-$seed"
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(raw.toByteArray(Charsets.UTF_8))
            .take(8)
            .joinToString("") { "%02X".format(it) }
        return "ANDROID-$digest"
    }
}
