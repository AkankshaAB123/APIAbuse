package com.threatguard.agent.api

import android.content.Context
import android.content.SharedPreferences

object ApiClient {
    private const val PREFS_NAME = "threatguard_settings"
    private const val KEY_BASE_URL = "backend_base_url"
    private const val KEY_AUTH_TOKEN = "auth_token"
    private const val KEY_AUTH_USERNAME = "auth_username"
    private const val KEY_AUTH_ROLE = "auth_role"
    private const val KEY_AUTH_DEVICE_IP = "auth_device_ip"

    const val DEFAULT_EMULATOR_URL = "http://10.0.2.2:8000/"

    private var apiInstance: ThreatGuardApi? = null

    fun getInstance(context: Context): ThreatGuardApi {
        if (apiInstance == null) {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val savedUrl = prefs.getString(KEY_BASE_URL, DEFAULT_EMULATOR_URL) ?: DEFAULT_EMULATOR_URL
            val savedToken = prefs.getString(KEY_AUTH_TOKEN, null)
            apiInstance = ThreatGuardApi(savedUrl, savedToken)
        }
        return apiInstance!!
    }

    fun saveBaseUrl(context: Context, newUrl: String) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().putString(KEY_BASE_URL, newUrl.trim()).apply()
        getInstance(context).updateBaseUrl(newUrl)
    }

    fun getSavedBaseUrl(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString(KEY_BASE_URL, DEFAULT_EMULATOR_URL) ?: DEFAULT_EMULATOR_URL
    }

    fun saveAuthSession(
        context: Context,
        token: String,
        username: String,
        role: String,
        deviceIp: String?
    ) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit()
            .putString(KEY_AUTH_TOKEN, token)
            .putString(KEY_AUTH_USERNAME, username)
            .putString(KEY_AUTH_ROLE, role)
            .putString(KEY_AUTH_DEVICE_IP, deviceIp)
            .apply()
        getInstance(context).updateAuthToken(token)
    }

    fun clearAuthSession(context: Context) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit()
            .remove(KEY_AUTH_TOKEN)
            .remove(KEY_AUTH_USERNAME)
            .remove(KEY_AUTH_ROLE)
            .remove(KEY_AUTH_DEVICE_IP)
            .apply()
        getInstance(context).updateAuthToken(null)
    }

    fun getSavedToken(context: Context): String? {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString(KEY_AUTH_TOKEN, null)
    }

    fun getSavedUsername(context: Context): String? {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString(KEY_AUTH_USERNAME, null)
    }

    fun getSavedRole(context: Context): String? {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString(KEY_AUTH_ROLE, null)
    }

    fun getSavedDeviceIp(context: Context): String? {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString(KEY_AUTH_DEVICE_IP, null)
    }

    fun isAuthenticated(context: Context): Boolean {
        return !getSavedToken(context).isNullOrBlank()
    }
}
