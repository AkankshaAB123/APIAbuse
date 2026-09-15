package com.threatguard.agent.api

import android.content.Context
import android.content.SharedPreferences

object ApiClient {
    private const val PREFS_NAME = "threatguard_settings"
    private const val KEY_BASE_URL = "backend_base_url"
    const val DEFAULT_EMULATOR_URL = "http://10.0.2.2:8000/"

    private var apiInstance: ThreatGuardApi? = null

    fun getInstance(context: Context): ThreatGuardApi {
        if (apiInstance == null) {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val savedUrl = prefs.getString(KEY_BASE_URL, DEFAULT_EMULATOR_URL) ?: DEFAULT_EMULATOR_URL
            apiInstance = ThreatGuardApi(savedUrl)
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
}
