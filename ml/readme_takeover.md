
The ML module has two separate responsibilities:

1. Supervised attack detection
2. Unsupervised anomaly detection

The ML module provides clean Python interfaces and an HTTP API so other members can use the models without needing to know how the models work internally.

---

# 1. Architecture

The current ML pipeline is:

                    Network Features
                           |
                           |
                    Raw feature data
                           |
              +------------+------------+
              |                         |
              v                         v
       XGBoost Predictor        Isolation Forest
              |                  Anomaly Detector
              |                         |
           Scaler                    Scaler
              |                         |
              v                         v
       Attack Prediction          Anomaly Result
              |                         |
              +------------+------------+
                           |
                           v
                       ML API
                       app.py
                           |
                           v
                    HTTP JSON Response


The ML module does NOT perform:

- Risk scoring
- API-specific attack rules
- The 10 enterprise API attack detectors
- MongoDB operations
- React/frontend work
- FastAPI
- Business logic for the application

Those responsibilities belong to other members.

---

# 2. Dataset

The ML models were trained using the CICIDS2017 dataset.

Original dataset:

- 8 CSV files
- Approximately 2.83 million network-flow rows
- 79 columns including the target label

The preprocessing pipeline:

1. Loaded all CICIDS2017 CSV files
2. Combined them
3. Cleaned column names
4. Removed infinite values
5. Removed missing values
6. Converted labels into a binary `Attack` column
7. Performed a duplicate-safe train/test split
8. Scaled features using `StandardScaler`

Final dataset:

```text
Total rows: 2,827,876
Total columns: 79

BENIGN:
2,271,320

ATTACK:
556,556

To test: run app.py along with test_api.py for the final prediction
Output:
{
    "prediction": "BENIGN",
    "attack_probability": 0.000985,
    "benign_probability": 0.999015,
    "is_anomaly": false,
    "anomaly_score": 0.3204555,
    "model": "xgboost"
}