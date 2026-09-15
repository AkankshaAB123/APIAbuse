package com.threatguard.agent.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val CyberNavy = Color(0xFF0A0E1A)
val CyberSurface = Color(0xFF131B2E)
val CyberSurfaceVariant = Color(0xFF1C2740)
val NeonCyan = Color(0xFF00E5FF)
val NeonGreen = Color(0xFF00E676)
val WarningAmber = Color(0xFFFFB300)
val DangerRed = Color(0xFFFF1744)
val TextPrimary = Color(0xFFF0F4F8)
val TextSecondary = Color(0xFF94A3B8)

private val DarkColorScheme = darkColorScheme(
    primary = NeonCyan,
    onPrimary = Color.Black,
    primaryContainer = CyberSurfaceVariant,
    onPrimaryContainer = NeonCyan,
    secondary = NeonGreen,
    onSecondary = Color.Black,
    background = CyberNavy,
    onBackground = TextPrimary,
    surface = CyberSurface,
    onSurface = TextPrimary,
    surfaceVariant = CyberSurfaceVariant,
    onSurfaceVariant = TextSecondary,
    error = DangerRed,
    onError = Color.White
)

@Composable
fun ThreatGuardTheme(
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        content = content
    )
}
