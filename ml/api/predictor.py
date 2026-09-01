import pandas as pd
import joblib
from pathlib import Path


# =========================================================
# PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_PATH = BASE_DIR / "models" / "xgboost.pkl"
SCALER_PATH = BASE_DIR / "models" / "scaler.pkl"


# =========================================================
# LOAD MODEL AND SCALER ONCE
# =========================================================

print("Loading XGBoost model...")

model = joblib.load(MODEL_PATH)

print("XGBoost model loaded successfully.")


print("Loading scaler...")

scaler = joblib.load(SCALER_PATH)

print("Scaler loaded successfully.")


# =========================================================
# PREDICTION
# =========================================================

def predict(features):
    """
    Predict whether network traffic is benign or an attack.

    Input:
        Raw feature dictionary.

    Output:
        {
            "prediction": "BENIGN" or "ATTACK",
            "attack_probability": float,
            "benign_probability": float,
            "model": "xgboost"
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
    # Convert features to DataFrame
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
    # XGBoost prediction
    # -----------------------------------------------------

    prediction = int(model.predict(X_scaled)[0])


    # -----------------------------------------------------
    # Prediction probabilities
    # -----------------------------------------------------

    probabilities = model.predict_proba(X_scaled)[0]

    benign_probability = float(probabilities[0])
    attack_probability = float(probabilities[1])


    # -----------------------------------------------------
    # Convert prediction to label
    # -----------------------------------------------------

    if prediction == 1:
        label = "ATTACK"
    else:
        label = "BENIGN"


    # -----------------------------------------------------
    # Return standardized result
    # -----------------------------------------------------

    return {
        "prediction": label,
        "attack_probability": attack_probability,
        "benign_probability": benign_probability,
        "model": "xgboost"
    }