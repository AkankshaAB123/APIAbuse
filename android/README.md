# ThreatGuard Mobile Agent (Android)

Native Android security agent and simulation client for the **ThreatGuard Intelligent Cloud Intrusion Detection & API Abuse Detection System**.

---

## 1. Overview & Architecture

ThreatGuard Mobile operates as a client-side endpoint monitoring agent that communicates directly with the centralized ThreatGuard FastAPI backend:

```
Android ThreatGuard App
        ? (Legitimate device metrics OR safe synthetic simulation telemetry)
ApiSecurityEvent JSON Contract
        ?
POST /events (FastAPI backend)
        ?
EventProcessor Pipeline:
  +-- 21 Registered Detectors (Deterministic & Heuristic)
  +-- ML Engine (XGBoost Multiclass + Isolation Forest Anomaly Detection)
  +-- Risk Engine (Composite 0-100 Score & Risk Level)
  +-- Impact Service (8 Concrete Consequences: Financial Loss, Endpoint Compromise, etc.)
  +-- Mitigation Service (7 Actions: ALLOW, MONITOR, RATE_LIMIT, BLOCK, QUARANTINE, TRANSACTION_BLOCK, URL_BLOCK)
  +-- RAG + Gemini AI (14 Knowledge Base Guides + Contextual Reasoning)
        ?
MongoDB Incident Persistence
        ?
SOC Frontend Dashboard & Real-Time In-App Result Display
```

---

## 2. Project Prerequisites

- **Android Studio**: Android Studio Hedgehog (2023.1.1) or newer (Koala / Ladybug recommended).
- **JDK**: Java 17 or Java 21 (bundled with Android Studio or Eclipse Adoptium).
- **Android SDK**:
  - `compileSdk`: 34 (Android 14)
  - `targetSdk`: 34
  - `minSdk`: 26 (Android 8.0 Oreo or newer)
- **Gradle**: 8.7 (configured via Gradle wrapper)
- **UI Toolkit**: Jetpack Compose with Material 3 Dark Theme.

---

## 3. How to Build the APK

### In Android Studio
1. Open Android Studio.
2. Select **Open**, and browse to `C:\New folder\MAJOR PROJECT\APIAbuse-INTEGRATION\android`.
3. Allow Gradle to sync dependencies.
4. Select **Build** > **Build Bundle(s) / APK(s)** > **Build APK(s)**.
5. The generated APK will be located at:
   `android/app/build/outputs/apk/debug/app-debug.apk`

### From Command Line (Windows PowerShell / CMD)
```powershell
cd "C:\New folder\MAJOR PROJECT\APIAbuse-INTEGRATION\android"
.\gradlew.bat assembleDebug
```
The output APK is generated at:
`app\build\outputs\apk\debug\app-debug.apk`

---

## 4. Backend Connection Configuration

The ThreatGuard backend must be running to receive events:

```powershell
cd "C:\New folder\MAJOR PROJECT\APIAbuse-INTEGRATION"
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

### A. Testing on Android Emulator
- The Android Emulator routes host machine loopback through `10.0.2.2`.
- Default backend URL configured in the app:
  `http://10.0.2.2:8000/`

### B. Testing on a Physical Android Device
1. Ensure your Android phone and development PC are connected to the same Wi-Fi network.
2. Find your PC IP address using `ipconfig` (e.g. `192.168.1.50`).
3. Open **ThreatGuard Mobile** > tap **Settings** tab.
4. Enter:
   `http://192.168.1.50:8000/`
5. Tap **Save URL**, then tap **Test Connection** to confirm connectivity.

---

## 5. Security Scenarios & Simulation Lab

The app includes a dedicated **Controlled Security Lab** allowing safe demonstrations of threat detection:

1. **Suspicious App Behavior**: Generates synthetic process execution metadata (`powershell.exe -EncodedCommand`) triggering endpoint detection and `QUARANTINE` mitigation.
2. **Accessibility Keyhook Simulation**: Simulates unauthorized accessibility service hooking touch and keystrokes (`keyboard_hook=true`), triggering credential protection and `QUARANTINE`.
3. **Fake Banking Lookalike URL**: Simulates navigation to a deceptive financial portal (`secure-login-verify-bank-account.info`), evaluated by the backend phishing detector and assigned `URL_BLOCK`.
4. **Fraudulent Shopping Checkout**: Simulates price and coupon tampering during checkout (`/api/orders/checkout`), assigned `TRANSACTION_BLOCK` mitigation.
5. **Session Replay / Unauthorized Transfer**: Simulates high-value transaction replay using an unauthorized session token (`/api/transactions/transfer`), triggering financial loss mitigation.
6. **Anomalous Outbound Shell**: Generates telemetry representing an unexpected outbound socket connection from a shell process, triggering host threat detection and `QUARANTINE`.

---

## 6. Real-Time Security Companion

The Android application works **bidirectionally** — it is not only a telemetry sender but also a **real-time security companion** that surfaces threats detected across the entire ThreatGuard ecosystem (including laptop-originating incidents).

### Architecture

```
ThreatGuard Backend (FastAPI)
    │
    ├── POST /events  ←  Android sends telemetry / simulation events
    │
    └── GET /threats   →  Android polls for ALL detected incidents
    └── GET /threats/{id} → Android fetches full incident details + AI analysis
              │
              ▼
    ThreatMonitor (Kotlin coroutine, 5s polling)
              │
              ├── StateFlow<List<ThreatSummary>> → Incidents Tab UI
              └── ThreatNotificationManager → Native Android notifications
```

### Key Components

| Component | Location | Purpose |
|-----------|----------|---------|
| `ThreatMonitor` | `service/ThreatMonitor.kt` | Coroutine-based poller (5s interval), deduplication via `seenEventIds`, lifecycle-aware (starts on `onResume`, stops on `onPause`) |
| `ThreatNotificationManager` | `notification/ThreatNotificationManager.kt` | Android notification channel, severity-based filtering, Android 13+ `POST_NOTIFICATIONS` permission handling |
| `ThreatIncident` models | `model/ThreatIncident.kt` | `ThreatSummary` (list view) and `ThreatDetail` (full document with AI analysis) |
| `RealIncidentsListScreen` | `ui/Screens.kt` | Live threat list with severity color coding and risk scores |
| `IncidentDetailScreen` | `ui/Screens.kt` | Full incident detail view including Gemini AI analysis |

### Notification Behavior

- **Threshold**: Notifications fire for `HIGH` / `CRITICAL` severity OR `riskScore ≥ 75.0`
- **Deduplication**: Each `event_id` is tracked in memory; a notification fires at most once per incident
- **First-load suppression**: On initial poll, all existing incidents are silently loaded (no spam of historical notifications)
- **Permission**: Android 13+ requires runtime `POST_NOTIFICATIONS` — the app requests this at launch

### 5-Tab Navigation

| Tab | Content |
|-----|---------|
| 🛡 Security | Home dashboard — device health telemetry + latest backend incidents |
| 🔔 Incidents | Full list of all backend-detected threats, tappable for detail view |
| 🧪 Lab | Controlled Security Lab with 6 safe simulation scenarios |
| 📋 History | Event submission history with processing results |
| ⚙ Settings | Backend URL configuration, connection test, app info |

---

## 7. Safety & Non-Destructive Principles

- **No Dangerous Permissions**: The application requires only `INTERNET`, `ACCESS_NETWORK_STATE`, and `POST_NOTIFICATIONS` (Android 13+). It does NOT request root privileges, SMS reading, contacts access, fine location, or device administration.
- **Pure Synthetic Telemetry**: Simulations construct in-memory Pydantic-compatible JSON envelopes. No malicious binaries, keystroke loggers, reverse shells, or real network exploits are executed.
- **Safe Development Network Config**: `network_security_config.xml` permits cleartext HTTP only for local development domains (`10.0.2.2`, `localhost`, `192.168.*`).
- **No Fake Alerts**: Every notification and incident displayed on Android corresponds to an actual backend-processed event. The app never fabricates threat data client-side.
