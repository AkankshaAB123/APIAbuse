import pandas as pd
import joblib
from pathlib import Path


# =========================================================
# PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_PATH = BASE_DIR / "models" / "isolation_forest.pkl"
SCALER_PATH = BASE_DIR / "models" / "scaler.pkl"


# =========================================================
# LOAD MODEL AND SCALER ONCE
# =========================================================

print("Loading Isolation Forest...")

model = joblib.load(MODEL_PATH)

print("Isolation Forest loaded successfully.")


print("Loading scaler...")

scaler = joblib.load(SCALER_PATH)

print("Scaler loaded successfully.")


# =========================================================
# ANOMALY DETECTION
# =========================================================

def detect_anomaly(features):
    """
    Detect whether network traffic is anomalous.

    Input:
        Raw feature dictionary.

    Output:
        {
            "is_anomaly": True/False,
            "anomaly_score": float
        }
    """

    # -----------------------------------------------------
    # Validate input
    # -----------------------------------------------------

    if not isinstance(features, dict):
        raise ValueError("features must be a dictionary")

    if not features:
        raise ValueError("features cannot be empty")


    # -----------------------------------------------------
    # Convert to DataFrame
    # -----------------------------------------------------

    X = pd.DataFrame([features])


    # -----------------------------------------------------
    # Make sure feature order matches training
    # -----------------------------------------------------

    if hasattr(scaler, "feature_names_in_"):

        expected_features = list(scaler.feature_names_in_)

        missing_features = [
            feature
            for feature in expected_features
            if feature not in X.columns
        ]

        if missing_features:

            raise ValueError(
                f"Missing required features: {missing_features}"
            )

        X = X[expected_features]


    # -----------------------------------------------------
    # SCALE FEATURES
    # -----------------------------------------------------

    X_scaled = scaler.transform(X)


    # -----------------------------------------------------
    # Isolation Forest prediction
    # -----------------------------------------------------

    prediction = model.predict(X_scaled)[0]


    # Isolation Forest:
    #
    #  1  = normal
    # -1  = anomaly

    is_anomaly = prediction == -1


    # -----------------------------------------------------
    # Anomaly score
    # -----------------------------------------------------

    score = float(
        model.decision_function(X_scaled)[0]
    )


    # -----------------------------------------------------
    # Return result
    # -----------------------------------------------------

    return {
        "is_anomaly": bool(is_anomaly),
        "anomaly_score": score
    }