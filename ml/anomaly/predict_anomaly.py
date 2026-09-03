import pandas as pd
import joblib

from pathlib import Path


# =========================================================
# PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_FILE = (
    BASE_DIR
    / "models"
    / "isolation_forest.pkl"
)


# =========================================================
# LOAD MODEL
# =========================================================

print("Loading Isolation Forest...")

model = joblib.load(MODEL_FILE)

print("Isolation Forest loaded successfully.")


# =========================================================
# PREDICT ANOMALY
# =========================================================

def predict_anomaly(features):
    """
    Predict whether a network flow is anomalous.

    Parameters
    ----------
    features : dict
        Network flow features.

    Returns
    -------
    dict
        Anomaly prediction and score.
    """

    # -----------------------------------------------------
    # Convert input to DataFrame
    # -----------------------------------------------------

    X = pd.DataFrame([features])

    # -----------------------------------------------------
    # Get Isolation Forest prediction
    #
    #  1  = normal
    # -1  = anomaly
    # -----------------------------------------------------

    prediction = model.predict(X)[0]

    # -----------------------------------------------------
    # Get raw anomaly score
    # -----------------------------------------------------

    raw_score = model.decision_function(X)[0]

    # -----------------------------------------------------
    # Convert to anomaly score
    #
    # Higher = more anomalous
    # -----------------------------------------------------

    anomaly_score = 1 - raw_score

    # Keep score between 0 and 1
    anomaly_score = max(
        0.0,
        min(1.0, float(anomaly_score))
    )

    # -----------------------------------------------------
    # Determine anomaly
    # -----------------------------------------------------

    is_anomaly = prediction == -1

    # -----------------------------------------------------
    # Return result
    # -----------------------------------------------------

    return {
        "is_anomaly": bool(is_anomaly),
        "anomaly_score": anomaly_score
    }


# =========================================================
# TEST
# =========================================================

if __name__ == "__main__":

    print("\nTesting Isolation Forest...")

    # Load one test row
    TEST_FILE = (
        BASE_DIR
        / "datasets"
        / "processed"
        / "test_scaled.csv"
    )

    df = pd.read_csv(TEST_FILE)

    features = (
        df.drop(columns=["Attack"])
        .iloc[0]
        .to_dict()
    )

    result = predict_anomaly(features)

    print("\nAnomaly result:")

    print(result)

    print("\nActual label:")

    if df["Attack"].iloc[0] == 1:
        print("ATTACK")
    else:
        print("BENIGN")

    print("\n" + "=" * 70)
    print("ANOMALY PREDICTION TEST COMPLETE")
    print("=" * 70)