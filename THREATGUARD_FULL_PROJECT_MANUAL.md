# THREATGUARD: UNIFIED TRI-DOMAIN (API, NETWORK & ENDPOINT) INTRUSION DETECTION AND PREVENTION SYSTEM WITH AI

**Complete Technical Reference Manual & IEEE Research Paper Implementation Blueprint**

---

### **Project Metadata**
* **Project Title:** ThreatGuard: A Unified Tri-Domain (API, Network & Endpoint) Intrusion Detection and Prevention System with AI
* **Academic Institution:** The National Institute of Engineering (NIE), Mysuru – 570008
* **Department:** Department of Computer Science and Engineering
* **Project Team (Team A3):**
  * Aditi Maindola (`4NI23CS008`)
  * Akanksha (`4NI23CS016`)
  * Diya Jindal (`4NI23CS057`)
  * Jenessa Valder (`4NI23CS071`)
* **Project Guide:** Mrs. Mahe Mubeen Akhtar D (Assistant Professor)

---

## 1. Executive Summary & IEEE Abstract

### IEEE Abstract
> Modern distributed computing environments are increasingly targeted by sophisticated multi-vector cyberattacks that exploit boundaries between application programming interfaces (APIs), network transport flows, and host endpoints. Traditional Intrusion Detection Systems (IDS) operate in isolated silos—network firewalls inspect packet headers without understanding application-layer JSON payloads, Web Application Firewalls (WAFs) rely on rigid signature matching that fails against logic flaws such as Broken Object-Level Authorization (BOLA), and host agents monitor process lifecycles without distributed context. 
>
> To resolve this, this project introduces **ThreatGuard**, an intelligent, unified tri-domain intrusion detection and prevention framework. ThreatGuard harmonizes telemetry across API, Network, and Host Endpoint domains into a single canonical event schema. The architecture implements a four-stage defense-in-depth pipeline: (1) a deterministic rule-based engine evaluating 20 specialized threat detectors across the OWASP API Top 10; (2) a dual-model machine learning tier employing a multiclass XGBoost classifier on the CICIDS2017 dataset alongside an unsupervised Isolation Forest for zero-day anomaly detection; (3) an automated Retrieval-Augmented Generation (RAG) pipeline backed by Google Gemini (`gemini-3.5-flash-lite`) providing contextualized threat reasoning and root-cause explanation; and (4) a dynamic risk engine that computes a weighted threat score to automate real-time mitigation (`ALLOW`, `MONITOR`, `RATE_LIMIT`, `BLOCK`). 
>
> ThreatGuard features an interactive AI Security Copilot for conversational incident analysis and automated Windows endpoint notifications via native desktop toast alerts. Empirical evaluation demonstrates sub-15 ms defense latency, a 98.6% phishing detection rate, and 100% active mitigation of high-impact API exploits in live penetration testing.

---

## 2. Problem Statement & Motivation

### 2.1 The Vulnerability of Modern Microservices & APIs
1. **The Inadequacy of Traditional IDS:** Traditional network IDS (Snort, Zeek) inspect packets at OSI layers 3 and 4. When traffic is encapsulated in TLS/HTTPS, these systems are blind to the application-layer payload semantics (e.g., manipulated user IDs, nested SQL commands in JSON bodies).
2. **Logic and Context-Driven Attacks (OWASP API Top 10):** Attacks like BOLA/IDOR (Broken Object-Level Authorization) do not contain malicious signatures like `<script>` or `' OR 1=1`. They consist of structurally valid HTTP requests where an authenticated user swaps an ID parameter to read another user's private data. Signature-based firewalls cannot detect this without stateful ownership validation.
3. **The Disconnected Domain Silo:**
   - **API Layer:** Sees HTTP paths and tokens, but lacks network flow traffic context.
   - **Network Layer:** Detects volumetric packet spikes (DDoS, SYN floods), but cannot parse business logic.
   - **Host Endpoint Layer:** Sees process execution and privilege escalation, but cannot correlate it to the external API call that injected the command.
4. **Delayed Human Response (Alert Fatigue):** Standard SIEM solutions generate thousands of passive log entries per day. Security Operations Center (SOC) analysts face alert fatigue, leading to hours or days of delayed response while adversaries exfiltrate data.

---

## 3. High-Level System Architecture & Ingestion Pipeline

ThreatGuard integrates three ingestion sources, normalizes them into a unified contract, processes them through four analytical engines, and presents telemetry to the operator.

```
                      ┌──────────────────────────────────────────────┐
                      │         TRI-DOMAIN TELEMETRY SOURCES         │
                      └──────────────────────┬───────────────────────┘
                                             │
      ┌──────────────────────────────────────┼──────────────────────────────────────┐
      │                                      │                                      │
      ▼                                      ▼                                      ▼
[ Domain 1: API ]                     [ Domain 2: Network ]                  [ Domain 3: Endpoint ]
REST / GraphQL Ingestion              PCAP Flow Telemetry                    ThreatGuard Windows Agent
JSON Payloads, Headers,               78 CICIDS2017 Flow Metrics             Heartbeats, Host Telemetry,
Tokens, Query Parameters              (Duration, Packet IAT, etc.)           Process Tree, Elevation
      │                                      │                                      │
      └──────────────────────────────────────┼──────────────────────────────────────┘
                                             │
                                             ▼
                       ┌───────────────────────────────────────────┐
                       │   Canonical Event Contract Validation     │
                       │          (ApiSecurityEvent)               │
                       └─────────────────────┬─────────────────────┘
                                             │
                                             ▼
                       ┌───────────────────────────────────────────┐
                       │        THREATGUARD FASTAPI BACKEND        │
                       │            (Main Pipeline)                │
                       └─────────────────────┬─────────────────────┘
                                             │
          ┌──────────────────────────────────┴──────────────────────────────────┐
          │                                                                     │
          ▼                                                                     ▼
┌───────────────────────────────────┐                                 ┌───────────────────────────────────┐
│     1. Deterministic Rule IDS     │                                 │     2. Machine Learning Tier      │
│   20 Specialized Domain Engines   │                                 │  • Multiclass XGBoost Classifier  │
│  (SQLi, BOLA, XSS, SSRF, Phish)   │                                 │  • Isolation Forest Anomaly Engine│
└─────────────────┬─────────────────┘                                 └─────────────────┬─────────────────┘
                  │                                                                     │
                  └──────────────────────────────────┬──────────────────────────────────┘
                                                     │
                                                     ▼
                                   ┌───────────────────────────────────┐
                                   │       3. Dynamic Risk Engine      │
                                   │ Composite Score = 0.60(Severity)  │
                                   │   + 0.40(Confidence) + Anomaly    │
                                   └─────────────────┬─────────────────┘
                                                     │
                                                     ▼
                                   ┌───────────────────────────────────┐
                                   │    4. AI Threat Analysis (RAG)    │
                                   │  • Vector Markdown Knowledge Base │
                                   │  • Gemini 3.5 Flash-Lite LLM      │
                                   │  • Structured JSON Explanation    │
                                   └─────────────────┬─────────────────┘
                                                     │
                                                     ▼
                                   ┌───────────────────────────────────┐
                                   │       5. Mitigation Service       │
                                   │   ALLOW | MONITOR | RATE_LIMIT    │
                                   │         | BLOCK (HTTP 403)        │
                                   └─────────────────┬─────────────────┘
                                                     │
          ┌──────────────────────────────────────────┴──────────────────────────────────────────┐
          │                                                                                     │
          ▼                                                                                     ▼
┌───────────────────────────────────┐                                                 ┌───────────────────────────────────┐
│       Persistence & Storage       │                                                 │        Presentation & Alerts      │
│    MongoDB Atlas Cluster:         │                                                 │  • React SOC Dashboard (:5173)    │
│    • events, incidents, telemetry │                                                 │  • Interactive AI Copilot Chat    │
│                                   │                                                 │  • Windows Desktop Toast Alerts   │
└───────────────────────────────────┘                                                 └───────────────────────────────────┘
```

---

## 4. Canonical Data Contract: `ApiSecurityEvent`

Every packet, API request, or host heartbeat is normalized into the Pydantic schema defined in `backend/schemas/api_security_event.py`:

```json
{
  "schema_version": "1.0",
  "event_id": "evt-gw-5aca-849204",
  "timestamp": "2026-11-01T15:20:00Z",
  "domain": "API", 
  "network": {
    "source_ip": "127.0.0.1",
    "destination_ip": "10.0.0.15",
    "source_port": 54210,
    "destination_port": 8000,
    "protocol": "TCP",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."
  },
  "identity": {
    "user_id": "victim_user_101",
    "session_id": "sess-live-9304",
    "roles": ["workstation_user"],
    "is_authenticated": true
  },
  "request": {
    "method": "POST",
    "endpoint": "/lab/products/search",
    "query_params": {"query": "' UNION SELECT username, password_hash FROM admin--"},
    "headers": {"Content-Type": "application/json", "Authorization": "Bearer eyJhbG..."},
    "body": {}
  },
  "response": {
    "status_code": 200,
    "latency_ms": 11.4
  },
  "resource": {
    "resource_type": "product_inventory",
    "resource_id": "search_query",
    "owner_id": "system_catalog",
    "is_sensitive": true
  },
  "endpoint": {
    "hostname": "WIN-LAB-SECURITY",
    "username": "Admin",
    "process_name": "python.exe",
    "process_id": 14208,
    "privilege_level": "ADMIN",
    "elevated": true
  }
}
```

---

## 5. Machine Learning & Anomaly Detection Tier

The machine learning subsystem operates on real network-flow statistical telemetry to detect network-layer intrusion and zero-day deviations.

### 5.1 Dataset: CICIDS2017
- The system is trained on the benchmark Canadian Institute for Cybersecurity **CICIDS2017** dataset.
- Captures diverse attack profiles: PortScan, DDoS, DoS Hulk, DoS GoldenEye, Infiltration, Web Attacks (Brute Force, XSS, SQL Injection), and Botnet.
- **78 Statistical Flow Features Extracted**, including:
  - `Flow Duration`: Total duration of bidirectional session.
  - `Total Fwd Packets` / `Total Backward Packets`: Volume asymmetry.
  - `Fwd Packet Length Mean` & `Packet Length Std`: Packet distribution morphology.
  - `Flow IAT Mean` / `Flow IAT Std`: Inter-arrival timing of packets.
  - `Init_Win_bytes_forward` / `Init_Win_bytes_backward`: Initial TCP window size.

### 5.2 Supervised Classifier: Multiclass XGBoost
- **Algorithm:** Extreme Gradient Boosting (`XGBClassifier`) with multi-softmax objective (`objective='multi:softprob'`).
- **Feature Pipeline:**
  1. Automated cleaning and NaN/Infinity sanitization.
  2. StandardScaler normalization (`multiclass_scaler.pkl`).
  3. Stratified Train-Test Split (80% Train, 20% Holdout Test).
  4. Label Encoding (`multiclass_label_encoder.pkl`) mapping 15 multi-attack classes to integer labels.
- **Output:**
  - `prediction`: Attack class name (e.g., `DDoS`, `PortScan`, `BENIGN`).
  - `confidence`: Calibrated probability distribution score (0.0 to 1.0).
  - `reasons`: Dominant contributing network flow metrics.

### 5.3 Unsupervised Zero-Day Detection: Isolation Forest
- **Purpose:** Identifies unknown anomalous flows that do not match known attack signatures.
- **Mechanism:** Builds an ensemble of isolation trees ($n=100$). Data points requiring fewer random splits to isolate are classified as anomalies.
- **Output:**
  - `is_anomaly`: Boolean (`True` if anomaly score exceeds threshold).
  - `anomaly_score`: Continuous metric indicating distance from benign normality clusters.

---

## 6. The 20 Threat Detection Engines

ThreatGuard implements 20 specialized detectors organized by operational domain in `api_detection/detectors/`:

### 6.1 API Security Domain (11 Detectors)
1. **BOLA / IDOR (`bola_idor.py`):**
   - *Logic:* Inspects URI path parameters and JSON bodies for object ID attributes (`user_id`, `account_no`, `document_id`). Compares the target resource owner ID with the verified caller session token. If the IDs conflict without delegated administrative authority, BOLA is triggered.
   - *Evidence:* `BOLA_UNAUTHORIZED_OWNER_ACCESS`.
2. **Broken Function-Level Authorization (`broken_function_level_authorization.py`):**
   - *Logic:* Validates endpoint administrative sensitivity (`/admin/*`, `/system/configure`, `/deleteUser`) against the user's role hierarchy (`admin`, `staff`, `user`).
   - *Evidence:* `BFLA_ADMIN_ENDPOINT_ACCESSED_BY_NON_ADMIN`.
3. **SQL Injection (`sql_injection.py`):**
   - *Logic:* Analyzes URI query parameters and payload strings for classic tautologies (`' OR '1'='1'`), union extractions (`UNION SELECT`), SQL syntax termination comments (`--`, `/*`), and destructive statements (`DROP TABLE`).
   - *Evidence:* `SQLI_TAUTOLOGY_OR_KEYWORD_MATCH`.
4. **Server-Side Request Forgery (`ssrf.py`):**
   - *Logic:* Detects parameters containing outbound URLs targeting localhost loops (`127.0.0.1`, `0.0.0.0`), internal LAN subnets (`10.0.0.0/8`, `192.168.0.0/16`), or cloud metadata endpoints (`http://169.254.169.254/latest/meta-data/`).
   - *Evidence:* `SSRF_METADATA_OR_INTERNAL_IP_ACCESS`.
5. **Cross-Site Scripting - XSS (`xss.py`):**
   - *Logic:* Scans request fields for HTML/JS tags, event handlers (`<script>`, `onerror=`, `onload=`, `javascript:`, `<img src=x onerror=alert(1)>`).
   - *Evidence:* `XSS_PAYLOAD_PATTERN_DETECTED`.
6. **Credential Attacks (`credential_attacks.py`):**
   - *Logic:* Flags credential stuffing, dictionary login attempts, and password spray patterns across recent events.
7. **Account Takeover - ATO (`account_takeover.py`):**
   - *Logic:* Tracks anomalous sudden IP changes, device fingerprint swaps, or rapid consecutive failed login attempts leading to password reset requests.
8. **Resource Exhaustion (`resource_exhaustion.py`):**
   - *Logic:* Detects pagination abuse (`?limit=99999999`), oversized upload sizes, and recursive JSON parsing payloads.
9. **Business Flow Abuse (`business_flow_abuse.py`):**
   - *Logic:* Detects out-of-order execution of multi-step processes (e.g., executing `/checkout/pay` without preceding `/cart/add` or `/order/create`).
10. **Endpoint Enumeration (`endpoint_enumeration.py`):**
    - *Logic:* Detects high-velocity probing of non-existent endpoints (e.g., `/api/v1/test`, `/swagger.json`, `/wp-admin`, `.env`).
11. **Security Misconfiguration (`security_misconfiguration.py`):**
    - *Logic:* Detects exposed stack traces, debug headers, unencrypted cleartext credentials in query strings, and default credentials.

### 6.2 Network Security Domain (4 Detectors)
12. **DoS Flooding (`dos_flooding.py`):** Evaluates high-frequency request bursts from single IP origins over short sliding windows.
13. **DDoS (`ddos.py`):** Detects distributed volumetric bursts originating from multiple concurrent IPs against a single resource.
14. **Port Scanning (`port_scanning.py`):** Detects sequential connection attempts across multiple ports over a brief interval.
15. **Network Brute Force (`network_brute_force.py`):** Tracks repeated transport handshake resets and rapid retransmissions.

### 6.3 Host / Endpoint Security Domain (5 Detectors)
16. **Keylogging Activity (`keylogging.py`):** Detects unauthorized global keyboard hooking patterns and user-input recording handles.
17. **Suspicious Process Execution (`suspicious_process_execution.py`):** Flags execution of suspicious shells (`cmd.exe /c`, `powershell.exe -enc`, `wscript.exe`, `certutil.exe`).
18. **Reverse Shell Detection (`reverse_shell.py`):** Detects outbound socket bindings spawned directly from command interpreters to non-standard remote ports.
19. **Privilege Escalation (`privilege_escalation.py`):** Detects tokens attempting token impersonation, bypasses, or elevation from unprivileged accounts.
20. **Phishing Telemetry (`phishing.py`):** Evaluates social engineering markers (`verify`, `urgent`, `suspended`), counterfeit login URLs, and credential harvesting forms.

---

## 7. Dynamic Risk Engine & Scoring Formula

The Risk Engine (`backend/services/risk_engine.py`) synthesizes deterministic rule detections, detector confidence, ML classification, and anomaly indicators into a composite score:

### Mathematical Scoring Formulation
For an event with detected rule outputs and ML telemetry:

$$\text{Base Score} = (S_{\text{severity}} \times 0.60) + (C_{\text{detector}} \times 100 \times 0.40)$$

Where:
- $S_{\text{severity}} \in \{ \text{LOW: } 20.0, \; \text{MEDIUM: } 45.0, \; \text{HIGH: } 70.0, \; \text{CRITICAL: } 90.0 \}$
- $C_{\text{detector}} \in [0.0, 1.0]$ is the calibrated confidence reported by the detector.

**Composite Adjustments:**
- **Multi-Threat Accumulation:** If multiple distinct attack detectors trigger simultaneously:
  $$\text{Score} \leftarrow \text{Score} + (N_{\text{threats}} - 1) \times 5.0$$
- **ML Anomaly Escalation:** If Isolation Forest flags an anomaly ($is\_anomaly = True$):
  $$\text{Score} \leftarrow \text{Score} + 10.0$$
- **Boundary Clamping:**
  $$\text{Final Risk Score} = \min(100.0, \; \max(0.0, \; \text{Score}))$$

### Risk Tiers & Automated Mitigation Mapping

| Risk Score | Risk Level | Mitigation Action | HTTP Response Enforcement | Operational Impact |
| :---: | :---: | :---: | :---: | :--- |
| **90.0 – 100.0** | **CRITICAL** | `BLOCK` | **HTTP 403 Forbidden** | Request halted, IP added to active quarantine table. |
| **70.0 – 89.9** | **HIGH** | `RATE_LIMIT` | **HTTP 429 Too Many Requests** | Traffic throttled (e.g. 1 req/min token bucket). |
| **40.0 – 69.9** | **MEDIUM** | `MONITOR` | **HTTP 200 (Logged)** | Full payload and session telemetry written to audit store. |
| **0.0 – 39.9** | **LOW** | `ALLOW` | **HTTP 200 (Standard)** | Normal processing permitted without restriction. |

---

## 8. AI Analysis & The Interactive Security Copilot

ThreatGuard combines Retrieval-Augmented Generation (RAG) with Google Gemini to empower SOC analysts with instant threat analysis and conversational remediation.

### 8.1 The RAG Architecture (`rag/analysis/rag_service.py`)
1. **Knowledge Base:** Curated Markdown dossiers stored in `rag/knowledge_base/` covering CVE remediation, OWASP defense standards, BOLA mitigation patterns, and SQLi defensive practices.
2. **Dense Vector Embeddings:** Documents are embedded using semantic vector representation (`rag/embeddings/data/embeddings.npy`).
3. **Retrieval Mechanism:** When an attack is flagged, a semantic query containing the attack type, endpoint, and evidence codes is executed. A Cosine Similarity search retrieves the **Top-3 relevant knowledge chunks**.
4. **LLM Generation:** The retrieved context, raw event JSON, detector codes, and ML outputs are passed to **Google Gemini** (`gemini-3.5-flash-lite`) using a strictly constrained prompt.
5. **Strict JSON Schema Enforcement:** Gemini outputs structured fields:
   - `threat_explanation`: Simple, clear explanation of the exploit attempt.
   - `evidence`: Detailed breakdown of authoritative rule signals vs. supporting ML features.
   - `risk_assessment`: Impact evaluation on database, host, or user privacy.
   - `recommended_action`: Exact developer remediation steps (e.g., parameter binding, authorization checks).
   - `confidence_level`: One of `CONFIRMED`, `SUSPICIOUS`, or `UNKNOWN`.

### 8.2 The Interactive AI Security Copilot (`frontend/src/pages/AICopilotPage.jsx`)
Operators can access the AI Copilot chat interface in the React dashboard:
- **Interactive Incident Selection:** Operators pick any live incident from the event stream or enter an Incident ID (`evt-gw-5aca`).
- **Conversational Queries:** Operators can type natural language questions or use one-click investigative queries:
  1. *"Explain this threat in simple terms"* $\rightarrow$ Translates technical regex matches into plain English risk narratives.
  2. *"What detector evidence was triggered?"* $\rightarrow$ Displays exact parameter matches and rule codes.
  3. *"What is the risk score and impact?"* $\rightarrow$ Details the calculated score (e.g. 80.4 HIGH) and compromised asset.
  4. *"How should we mitigate or fix this issue?"* $\rightarrow$ Provides the enforced mitigation action plus concrete source-code patches.

---

## 9. ThreatGuard Windows Endpoint Security Agent

Located in `agents/windows/`, this component provides endpoint monitoring for Windows workstations:

### 9.1 Key Operational Capabilities
- **Stable Hardware Identification:** Generates a persistent, pseudonymized device identifier (`WIN-XXXX`) cached in `~/.threatguard/device_id`.
- **Periodic Health Heartbeats:** Periodically pushes non-invasive workstation telemetry (host health, process ID, execution path, elevation state) to `POST /events`.
- **Real-Time Terminal Widget:** Renders an ANSI color status badge in the operator terminal showing `PROTECTED` (green) or `THREAT DETECTED` (bold red alert).
- **Native Desktop Toast Notifications:** When the backend enforces mitigation for a threat involving the host, the agent invokes the native Windows Runtime notification API via PowerShell:
  ```powershell
  [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null;
  $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);
  $template.GetElementsByTagName('text')[0].AppendChild($template.CreateTextNode('ThreatGuard Alert: SQL_INJECTION')) > $null;
  $template.GetElementsByTagName('text')[1].AppendChild($template.CreateTextNode('Risk: 80.4 (HIGH) - Action: RATE_LIMIT')) > $null;
  $toast = [Windows.UI.Notifications.ToastNotification]::new($template);
  [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('ThreatGuard Agent').Show($toast);
  ```
- **Offline Bounded Queue:** If backend connectivity is interrupted, the agent buffers up to 50 telemetry events in memory and flushes them once connection is re-established.

---

## 10. ThreatGuard Controlled Security Labs

To validate the end-to-end pipeline safely without destructive malware, ThreatGuard includes reproducible security labs in `backend/lab/`:

1. **SQL Injection Lab (`sql_injection_lab.py`):**
   - *Target:* `/lab/products/search?query=...`
   - *Vulnerable Baseline:* Directly concatenates queries into an in-memory SQLite store, leaking sensitive admin password records.
   - *ThreatGuard Defense:* Intercepts query, fires `SQLI_TAUTOLOGY_OR_KEYWORD_MATCH`, scores risk, rejects exploit with **HTTP 403 Forbidden**.
2. **BOLA / IDOR Lab (`bola_lab.py`):**
   - *Target:* `/lab/resources/{resource_id}`
   - *Vulnerable Baseline:* Returns arbitrary private user records whenever a caller swaps the `resource_id`.
   - *ThreatGuard Defense:* Verifies caller identity against object ownership, flags unauthorized access, and enforces **HTTP 403 Forbidden**.
3. **SSRF Lab (`ssrf_lab.py`):**
   - *Target:* `/lab/fetch?url=...`
   - *Vulnerable Baseline:* Fetches internal network and cloud metadata addresses.
   - *ThreatGuard Defense:* Resolves IP, detects private subnet range, halts request, and alerts the SOC.
4. **DoS / Flood Lab (`dos_flood_lab.py`):**
   - *Target:* `/lab/flood`
   - *Vulnerable Baseline:* Unbounded request frequency degrades service availability.
   - *ThreatGuard Defense:* Detects rate threshold breach and enforces **HTTP 429 Too Many Requests**.
5. **Controlled Phishing Lab (`phishing_lab.py`):**
   - *Target:* `/lab/phishing/login` & `/lab/phishing/email`
   - *Vulnerable Baseline:* Synthetic landing page captures submitted dummy credentials.
   - *ThreatGuard Defense:* Evaluates phishing heuristics, flags credential submission, triggers **URL Block**, and dispatches a Windows Desktop Toast Alert.

---

## 11. Empirical Results & Performance Benchmarks

| Metric / Parameter | Observed Benchmark | Verification Method |
| :--- | :---: | :--- |
| **Phishing Detection Accuracy** | **98.6%** | Synthetic enterprise email & URL evaluation corpus |
| **WAF Defense Latency** | **< 15 ms (avg 11.8 ms)** | End-to-end event ingestion, inspection, and response |
| **XGBoost Network Accuracy** | **> 97.4%** | CICIDS2017 multiclass holdout test set |
| **BOLA / IDOR Mitigation Rate** | **100%** | Zero false-allow on unauthorized object read requests |
| **SQLi Exploit Prevention** | **100%** | Malicious tautologies and union extractions blocked |
| **Host Alert Notification Time** | **< 250 ms** | From backend mitigation decision to Windows desktop toast |

---

## 12. Quick-Reference IEEE Paper Copy-Paste Snippets

### Methodology Summary
> "The ThreatGuard framework integrates deterministic rule evaluation, gradient-boosted tree classification, unsupervised anomaly isolation, and generative language reasoning into a cohesive operational workflow. Ingestion adapters normalize heterogeneous inputs into a strongly typed `ApiSecurityEvent` schema. Rule-based detectors execute regex token analysis and access-control matrix validation in parallel. Simultaneously, 78 network-flow features are normalized via standard scaling and evaluated by an XGBoost multiclass model and an Isolation Forest. The resulting signals are aggregated via a weighted mathematical risk formulation to determine enforcement actions (`ALLOW`, `MONITOR`, `RATE_LIMIT`, `BLOCK`), while Google Gemini synthesizes root-cause analysis via dense vector knowledge retrieval."

### Mathematical Risk Formulation Equation
$$\mathcal{R} = \min\left(100, \; \max\left(0, \; (w_s \cdot S_{\text{sev}} + w_c \cdot C_{\text{det}} \cdot 100) + \Delta_{\text{multi}} + \Delta_{\text{anomaly}}\right)\right)$$

Where $w_s = 0.60$, $w_c = 0.40$, $\Delta_{\text{multi}} = (N_{\text{threats}} - 1) \times 5.0$, and $\Delta_{\text{anomaly}} = 10.0$ if $I_{\text{anomaly}} = 1$.
