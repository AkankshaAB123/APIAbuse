
# APIAbuse — Intelligent API & Network Threat Detection System

APIAbuse is an intelligent security system designed to detect, analyze,
and respond to API-level and network-level security threats.

The system combines rule-based API attack detection, machine learning,
anomaly detection, risk assessment, mitigation recommendations,
MongoDB persistence, RAG/LLM-based explanations, and a React dashboard.

---

## 🚀 Features

- Detection of 10 enterprise/API attack categories
- Rule-based API security detectors
- Multiclass XGBoost network intrusion detection
- Isolation Forest anomaly detection
- Risk scoring and threat classification
- Mitigation recommendations
- MongoDB event and result persistence
- RAG/LLM-based threat explanations
- React security dashboard
- FastAPI backend integration

---

## 🛡️ Supported API Threats

1. BOLA / IDOR
2. Broken Function-Level Authorization / Privilege Escalation
3. Credential Attacks
4. Account Takeover / Valid Account Abuse
5. SQL Injection
6. SSRF
7. Resource Exhaustion / API Flooding
8. Sensitive Business-Flow Abuse / Automation
9. API Reconnaissance / Endpoint Enumeration
10. Security Misconfiguration / Exposed API

The API detectors handle API-level threats, while the ML component
focuses on network-flow based intrusion detection and anomaly detection.

CICIDS2017 is used for the network intrusion detection component and is
not claimed to directly represent all 10 API attack categories.

---

## 🏗️ System Architecture

```text
                 ┌───────────────────┐
                 │     Member 1      │
                 │   ML + Anomaly    │
                 │ XGBoost + IF      │
                 └─────────┬─────────┘
                           │
                           ▼
┌───────────────────┐   ┌───────────────────┐
│     Member 2      │   │     Member 3      │
│   API Detectors   │──▶│   FastAPI Backend  │
│   10 Threats      │   │   Risk + MongoDB   │
└───────────────────┘   │   + Mitigation     │
                        └─────────┬───────────┘
                                  │
                                  ▼
                        ┌───────────────────┐
                        │     Member 4      │
                        │   RAG + LLM +      │
                        │ React Dashboard    │
                        └───────────────────┘
````

---

## 🔄 Backend Processing Flow

```text
API Security Event
        │
        ▼
     FastAPI
        │
        ├───────────────┐
        ▼               ▼
 API Detectors       ML + Anomaly
        │               │
        └───────┬───────┘
                ▼
           Risk Engine
                │
                ▼
        Risk Assessment
                │
                ▼
           Mitigation
                │
                ▼
             MongoDB
                │
                ▼
        Backend Response
                │
                ▼
         React Dashboard
                │
                ▼
            RAG / LLM
```

---

## 🧠 Machine Learning

The ML component uses:

* CICIDS2017 dataset
* 78 network-flow features
* Multiclass XGBoost
* Isolation Forest anomaly detection

XGBoost provides:

```text
prediction
confidence
attack_explanation
reasons
model
```

Isolation Forest provides:

```text
is_anomaly
anomaly_score
```

### Run the ML Demo

From the repository root:

```bash
python -m ml.evaluation.demo_multiclass
```

---

## ⚙️ Backend

The backend is built using **FastAPI**.

Main endpoint:

```text
POST /events
```

The endpoint accepts:

* API security event information
* Optional ML network-flow features

The backend integrates:

```text
API Detectors
      +
XGBoost
      +
Isolation Forest
      ↓
Risk Engine
      ↓
Mitigation
      ↓
MongoDB
```

---

## 📊 Risk & Mitigation

### Risk Levels

| Risk Score | Level    |
| ---------- | -------- |
| 90–100     | CRITICAL |
| 70–89      | HIGH     |
| 40–69      | MEDIUM   |
| 0–39       | LOW      |

### Mitigation Recommendations

| Risk Level | Action     |
| ---------- | ---------- |
| LOW        | ALLOW      |
| MEDIUM     | MONITOR    |
| HIGH       | RATE_LIMIT |
| CRITICAL   | BLOCK      |

> Mitigation is currently recommendation-based and does not directly
> enforce blocking or rate limiting on production traffic.

---

## 🗄️ MongoDB

Processed events are persisted in MongoDB.

```text
Event
│
├── network
├── identity
├── request
├── response
├── resource
│
└── processing
    ├── detector_results
    ├── ml_result
    ├── risk_assessment
    └── mitigation_action
```

MongoDB configuration is stored locally in:

```text
backend/.env
```

Never commit `.env` or database credentials to GitHub.

---

## 📁 Project Structure

```text
APIAbuse/
│
├── api_detection/     # API attack detectors
├── backend/           # FastAPI, risk, database & mitigation
├── frontend/          # React dashboard
├── ml/                # ML & anomaly detection
├── rag/               # RAG / LLM components
├── tests/             # Backend tests
├── docs/              # Project documentation
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

## 🧪 Testing

Run the backend test suite:

```bash
python -m pytest .\tests -v
```

Current backend test status:

```text
9 passed
```

The tests cover:

* SQL Injection detection
* Benign event processing
* Invalid event validation
* MongoDB persistence
* FastAPI error handling
* Mitigation decisions for LOW, MEDIUM, HIGH and CRITICAL risk

---

## 👥 Team Responsibilities

| Member       | Responsibility                                      |
| ------------ | --------------------------------------------------- |
| **Member 1** | ML + Anomaly Detection                              |
| **Member 2** | 10 API Attack Detectors                             |
| **Member 3** | FastAPI + Integration + Risk + MongoDB + Mitigation |
| **Member 4** | RAG + LLM + React Dashboard                         |

---

## 📌 Current Status

```text
API Detection          ✅ Complete
ML + Anomaly           ✅ Complete
FastAPI Backend        ✅ Complete
Risk Engine            ✅ Complete (foundation)
MongoDB                ✅ Complete
Mitigation             ✅ Complete
Backend Testing        ✅ Complete
RAG                    ✅ Implemented
React Dashboard        ✅ Implemented
Final Integration      🔄 In Progress
```

---

## 🎯 Final Goal

APIAbuse aims to provide a unified security platform that can:

```text
Detect
  ↓
Analyze
  ↓
Assess Risk
  ↓
Recommend Mitigation
  ↓
Store Results
  ↓
Explain Threats
  ↓
Visualize Security Events
```

The final system combines:

**Known Threat Detection + ML Anomaly Analysis + Risk-Based Response +
RAG/LLM Security Explanation**

```
