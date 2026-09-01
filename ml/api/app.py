import sys
from pathlib import Path


# =========================================================
# PROJECT PATH
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(PROJECT_ROOT))


# =========================================================
# IMPORTS
# =========================================================

from flask import Flask, request, jsonify

from ml.api.predictor import predict
from ml.api.anomaly_detector import detect_anomaly


# =========================================================
# FLASK APP
# =========================================================

app = Flask(__name__)


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/", methods=["GET"])
def home():

    return jsonify({
        "message": "API Abuse ML API is running",
        "model": "XGBoost + Isolation Forest",
        "endpoints": [
            "GET /",
            "GET /health",
            "POST /predict"
        ]
    })


@app.route("/health", methods=["GET"])
def health():

    return jsonify({
        "status": "ok",
        "models": {
            "attack_detection": "xgboost",
            "anomaly_detection": "isolation_forest"
        }
    })


# =========================================================
# PREDICTION
# =========================================================

@app.route("/predict", methods=["POST"])
def prediction():

    try:

        # -------------------------------------------------
        # Get JSON
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
        # XGBoost prediction
        # -------------------------------------------------

        attack_result = predict(features)


        # -------------------------------------------------
        # Isolation Forest anomaly detection
        # -------------------------------------------------

        anomaly_result = detect_anomaly(features)


        # -------------------------------------------------
        # Combined response
        # -------------------------------------------------

        return jsonify({

            "prediction":
                attack_result["prediction"],

            "attack_probability":
                attack_result["attack_probability"],

            "benign_probability":
                attack_result["benign_probability"],

            "model":
                attack_result["model"],

            "is_anomaly":
                anomaly_result["is_anomaly"],

            "anomaly_score":
                anomaly_result["anomaly_score"]

        })


    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":

    print("=" * 60)
    print("ML API READY")
    print("=" * 60)

    print()
    print("Endpoints:")
    print("  GET  http://127.0.0.1:5000/")
    print("  GET  http://127.0.0.1:5000/health")
    print("  POST http://127.0.0.1:5000/predict")
    print()
    print("Starting server...")
    print()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )