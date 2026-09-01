from flask import Flask, request, jsonify

import pandas as pd
import joblib

from pathlib import Path

from risk_engine import calculate_risk


# =========================================================
# PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

XGBOOST_MODEL_FILE = (
    BASE_DIR
    / "models"
    / "xgboost.pkl"
)

ISOLATION_MODEL_FILE = (
    BASE_DIR
    / "models"
    / "isolation_forest.pkl"
)


# =========================================================
# LOAD MODELS
# =========================================================

print("=" * 70)
print("LOADING ML MODELS")
print("=" * 70)

print("\nLoading XGBoost model...")

xgboost_model = joblib.load(XGBOOST_MODEL_FILE)

print("XGBoost model loaded successfully.")


print("\nLoading Isolation Forest...")

isolation_model = joblib.load(ISOLATION_MODEL_FILE)

print("Isolation Forest loaded successfully.")


# =========================================================
# FLASK APP
# =========================================================

app = Flask(__name__)


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/health", methods=["GET"])
def health():

    return jsonify({
        "status": "ok",
        "models": [
            "xgboost",
            "isolation_forest"
        ]
    })


# =========================================================
# PREDICTION
# =========================================================

@app.route("/predict", methods=["POST"])
def predict():

    try:

        # -------------------------------------------------
        # Get JSON data
        # -------------------------------------------------

        data = request.get_json()

        if not data:

            return jsonify({
                "error": "No JSON data provided"
            }), 400


        # -------------------------------------------------
        # Get features
        # -------------------------------------------------

        features = data.get("features")

        if not features:

            return jsonify({
                "error": "Missing 'features'"
            }), 400


        # -------------------------------------------------
        # Convert features to DataFrame
        # -------------------------------------------------

        X = pd.DataFrame([features])


        # =================================================
        # XGBOOST
        # =================================================

        xgb_prediction = xgboost_model.predict(X)[0]

        probabilities = xgboost_model.predict_proba(X)[0]

        benign_probability = float(probabilities[0])

        attack_probability = float(probabilities[1])


        if xgb_prediction == 1:
            prediction = "ATTACK"
        else:
            prediction = "BENIGN"


        # =================================================
        # ISOLATION FOREST
        # =================================================

        isolation_prediction = isolation_model.predict(X)[0]

        raw_anomaly_score = (
            isolation_model
            .decision_function(X)[0]
        )


        # Isolation Forest:
        #
        #   1  = normal
        #  -1  = anomaly
        #

        is_anomaly = (
            isolation_prediction == -1
        )


        # =================================================
        # RISK ENGINE
        # =================================================

        risk_level = calculate_risk(
            attack_probability,
            is_anomaly
        )


        # =================================================
        # RESPONSE
        # =================================================

        return jsonify({

            # -------------------------------------------------
            # XGBoost
            # -------------------------------------------------

            "prediction": prediction,

            "attack_probability": attack_probability,

            "benign_probability": benign_probability,


            # -------------------------------------------------
            # Isolation Forest
            # -------------------------------------------------

            "is_anomaly": bool(is_anomaly),

            "anomaly_score": float(raw_anomaly_score),


            # -------------------------------------------------
            # Risk Engine
            # -------------------------------------------------

            "risk_level": risk_level

        })


    # =====================================================
    # ERROR HANDLING
    # =====================================================

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )