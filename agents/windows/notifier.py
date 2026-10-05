"""
Notification subsystem for the ThreatGuard Windows Endpoint Agent.

Displays security alerts as:
  1. Console banners (always, cross-platform)
  2. Windows Toast notifications (best-effort, via PowerShell)
"""
from __future__ import annotations

import logging
import subprocess
import sys

from agents.windows.api_client import BackendResponse

logger = logging.getLogger(__name__)

# Severity thresholds
_CRITICAL_SCORE = 80.0
_HIGH_SCORE = 60.0


class ThreatNotifier:
    """Issues console + OS-level notifications for detected threats."""

    def __init__(self, *, toast_enabled: bool = True) -> None:
        self._toast_enabled = toast_enabled and sys.platform == "win32"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def notify(self, response: BackendResponse) -> None:
        """Evaluate *response* and emit notifications if warranted."""
        if not response.success:
            logger.debug("Skipping notification — backend unreachable.")
            return

        if response.threat_detected:
            self._alert(response)
        else:
            self._safe(response)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _alert(self, r: BackendResponse) -> None:
        severity = self._severity_label(r.risk_score)
        attacks = ", ".join(r.attack_types) or "Unknown"
        banner = (
            f"\n{'='*60}\n"
            f"  [!] THREAT DETECTED [{severity}]\n"
            f"  Risk Score : {r.risk_score:.1f}\n"
            f"  Risk Level : {r.risk_level}\n"
            f"  Attack     : {attacks}\n"
            f"  Mitigation : {r.mitigation_action}\n"
            f"{'='*60}\n"
        )
        print(banner)
        logger.warning("THREAT DETECTED — score=%.1f attacks=%s", r.risk_score, attacks)

        if self._toast_enabled:
            self._toast(
                title=f"ThreatGuard — {severity} Threat",
                message=f"Attack: {attacks} | Score: {r.risk_score:.1f} | {r.mitigation_action}",
            )

    def _safe(self, r: BackendResponse) -> None:
        print(f"  [OK] Status: PROTECTED  (score={r.risk_score:.1f})")
        logger.info("Heartbeat OK — score=%.1f", r.risk_score)

    @staticmethod
    def _severity_label(score: float) -> str:
        if score >= _CRITICAL_SCORE:
            return "CRITICAL"
        if score >= _HIGH_SCORE:
            return "HIGH"
        return "MEDIUM"

    @staticmethod
    def _toast(title: str, message: str) -> None:
        """Send a Windows Toast notification via PowerShell (best-effort)."""
        ps_script = (
            "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, "
            "ContentType=WindowsRuntime] | Out-Null; "
            "$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
            "[Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
            f"$template.GetElementsByTagName('text')[0].AppendChild("
            f"$template.CreateTextNode('{title}')) | Out-Null; "
            f"$template.GetElementsByTagName('text')[1].AppendChild("
            f"$template.CreateTextNode('{message}')) | Out-Null; "
            "$toast = [Windows.UI.Notifications.ToastNotification]::new($template); "
            "[Windows.UI.Notifications.ToastNotificationManager]::"
            "CreateToastNotifier('ThreatGuard').Show($toast)"
        )
        try:
            subprocess.run(
                ["powershell", "-WindowStyle", "Hidden", "-Command", ps_script],
                timeout=5,
                check=False,
                capture_output=True,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Toast notification failed (non-fatal): %s", exc)
