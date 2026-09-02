# Member 1 --- ML Handover

## 1. How to Run the ML Demo

From the **root of the GitHub repository**, run:

``` bash
python -m ml.evaluation.demo_multiclass
```

This is the **main command for testing the complete ML component**.

The demo:

1.  Loads the CICIDS2017 dataset.
2.  Selects traffic samples from the dataset.
3.  Extracts the 78 network-flow features.
4.  Calls `predictor.py`.
5.  Runs the trained XGBoost multiclass model.
6.  Produces the ML prediction output as JSON.

### Important

Do **not** run `predictor.py` as the demo.

Use:

``` bash
python -m ml.evaluation.demo_multiclass
```

`demo_multiclass.py` calls `predictor.py` internally.

------------------------------------------------------------------------

# 2. Member 3 --- ML Integration

**Member 3 is responsible for integrating the ML component into the
backend.**

Member 3 must run the multiclass ML demo to verify the ML component and
see the exact JSON output:

``` bash
python -m ml.evaluation.demo_multiclass
```

The current flow is:

``` text
CICIDS/network-flow features
            ↓
   demo_multiclass.py
            ↓
       predictor.py
            ↓
      XGBoost model
            ↓
       Prediction JSON
            ↓
        MEMBER 3
```

### ML Detection Result

Member 3 should use the JSON output from `demo_multiclass.py` as the
**ML detection result** when integrating the ML component into the
backend.

The current JSON format is:

``` json
{
    "prediction": "DDoS",
    "confidence": 0.999997,
    "attack_explanation": {
        "summary": "The traffic was classified as DDoS because its network-flow behavior matched patterns learned from distributed denial-of-service traffic.",
        "characteristics": [
            "High traffic or packet volume",
            "Abnormal packet-rate behavior",
            "Flow characteristics associated with denial-of-service activity"
        ]
    },
    "reasons": [
        {
            "feature": "Flow Packets/s",
            "value": 12345.67,
            "importance": 0.18,
            "explanation": "Flow Packets/s is one of the features the trained model considers important when distinguishing network traffic classes."
        }
    ],
    "model": "xgboost_multiclass"
}
```

The important fields for Member 3 are:

``` text
prediction
confidence
attack_explanation
reasons
model
```

Member 3 can then combine this ML result with:

-   Member 2's API attack-detector results
-   anomaly information
-   risk scoring
-   database storage
-   mitigation logic

### What Member 3 needs to do

First verify the ML output by running:

``` bash
python -m ml.evaluation.demo_multiclass
```

Then integrate the predictor into the FastAPI backend.

The predictor can be called from Python with:

``` python
from ml.api.predictor import predict

result = predict(features)
```

The backend should preserve the same prediction JSON structure when
exposing the ML result to the rest of the application.

Member 3 **does not need to recreate the XGBoost logic**.

The ML component already handles the prediction.

------------------------------------------------------------------------

# 3. Member 2 --- API Attack Detectors

Member 2 does **not** own the ML component.

Member 2 owns the **10 enterprise API attack detectors**:

1.  BOLA / IDOR
2.  Broken Function-Level Authorization / Privilege Escalation
3.  Credential Attacks
4.  Account Takeover / Valid Account Abuse
5.  SQL Injection
6.  SSRF
7.  Resource Exhaustion / API Flooding
8.  Sensitive Business-Flow Abuse / Automation
9.  API Reconnaissance / Endpoint Enumeration
10. Security Misconfiguration / Exposed API

Member 2 provides their detection results to Member 3.

Member 3 then combines those results with the ML result.

------------------------------------------------------------------------

# 4. Member 3 --- Backend / Risk / Database Integration

Member 3 owns the central integration layer.

Expected responsibilities include:

``` text
FastAPI
Risk Engine
MongoDB
Mitigation
Integration
```

The overall integration is:

``` text
Member 1
ML prediction
+
Anomaly information
        │
        ▼
Member 3
FastAPI
Risk Engine
MongoDB
Mitigation
        ▲
        │
Member 2
10 API Attack Detectors
        │
        ▼
Member 3
        │
        ▼
Member 4
RAG + LLM + React Dashboard
```

Member 3 should normalize the information from Members 1 and 2 into the
application's common threat/event structure.

------------------------------------------------------------------------

# 5. Member 4 --- RAG / LLM / React Dashboard

Member 4 consumes the final information exposed by Member 3's backend.

Member 4 owns:

``` text
RAG
LLM
React Dashboard
```

The intended flow is:

``` text
Member 3 Backend
       ↓
     API
       ↓
Member 4 Frontend
       ↓
RAG / LLM / Dashboard
```

Member 4 does not need to interact directly with the XGBoost model.

------------------------------------------------------------------------

# 6. Member 1 → Member 3 Handover

The ML handoff is:

``` text
Member 1
    ↓
demo_multiclass.py
    ↓
predictor.py
    ↓
XGBoost
    ↓
JSON prediction
    ↓
Member 3
```

### Member 3's first step

Run:

``` bash
python -m ml.evaluation.demo_multiclass
```

This verifies that the ML component is working and shows the JSON
structure that Member 3 will integrate.

### Integration step

After verifying the demo, Member 3 can use:

``` python
from ml.api.predictor import predict

result = predict(features)
```

The resulting `result` should contain:

``` text
prediction
confidence
attack_explanation
reasons
model
```

This result becomes one of the inputs to the backend's risk/integration
layer.

------------------------------------------------------------------------

# 7. Overall Team Architecture

``` text
                    MEMBER 1
                 ML + Anomaly
                       │
                       │ ML JSON
                       ▼
                 ┌───────────┐
                 │ MEMBER 3  │
                 │ FastAPI   │
                 │ Risk      │
                 │ MongoDB   │
                 │ Mitigation│
                 └─────┬─────┘
                       ▲
                       │ API Detection Results
                       │
                 MEMBER 2
              10 API Detectors

                       │
                       ▼
                 MEMBER 3
                       │
                       │ Backend API
                       ▼
                 MEMBER 4
              RAG + LLM + React
```

------------------------------------------------------------------------

# 8. Responsibilities at a Glance

  -----------------------------------------------------------------------
  Member                  Responsibility          Handoff
  ----------------------- ----------------------- -----------------------
  **Member 1**            ML + anomaly detection  Prediction + anomaly
                                                  results

  **Member 2**            10 API attack detectors Detection + evidence +
                                                  confidence

  **Member 3**            FastAPI + integration + Final threat
                          risk + MongoDB +        information
                          mitigation              

  **Member 4**            RAG + LLM + React       Uses Member 3's backend
                          dashboard               
  -----------------------------------------------------------------------

------------------------------------------------------------------------

# 9. Current ML Status

The current ML component provides:

-   CICIDS2017 dataset-based testing
-   Multiclass XGBoost prediction
-   78 network-flow features
-   Confidence score
-   Attack explanation
-   Feature importance/reasons
-   JSON prediction output
-   `demo_multiclass.py` as the main test entry point

### Required ML demo command

``` bash
python -m ml.evaluation.demo_multiclass
```

**Member 3 should run this command when starting the ML integration.**

### Current integration boundary

``` text
ML side:
demo_multiclass.py
        ↓
predictor.py
        ↓
XGBoost
        ↓
JSON

Backend side:
JSON
  ↓
Member 3 / FastAPI
  ↓
Risk Engine
  ↓
MongoDB
  ↓
Mitigation
  ↓
Member 4 / Dashboard
```

Live network traffic/flow extraction is a separate integration step and
is not required to run the current dataset-based ML demo.
