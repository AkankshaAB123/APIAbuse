import pandas as pd
import joblib

from pathlib import Path


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "datasets" / "processed"
MODEL_DIR = BASE_DIR / "models"

TEST_FILE = DATA_DIR / "test_scaled.csv"
MODEL_FILE = MODEL_DIR / "xgboost.pkl"


# ---------------------------------------------------------
# Prediction
# ---------------------------------------------------------

def predict_row(row):

    # Load model
    model = joblib.load(MODEL_FILE)

    # Convert single row into DataFrame
    X = row.drop(labels=["Attack"]).to_frame().T

    # Prediction
    prediction = model.predict(X)[0]

    # Probability of attack
    probability = model.predict_proba(X)[0][1]

    if prediction == 1:
        label = "ATTACK"
    else:
        label = "BENIGN"

    return label, probability


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    print("=" * 70)
    print("XGBOOST PREDICTION TEST")
    print("=" * 70)

    print("\nLoading test data...")

    df = pd.read_csv(
        TEST_FILE,
        low_memory=False
    )

    print(f"Test rows: {len(df):,}")

    # Pick one row
    row = df.iloc[0]

    print("\nTesting prediction on first row...")

    label, probability = predict_row(row)

    print("\nPrediction:")
    print(f"  Label:       {label}")
    print(f"  Probability: {probability:.4f}")

    print("\nActual label:")

    if row["Attack"] == 1:
        print("  ATTACK")
    else:
        print("  BENIGN")

    print("\n" + "=" * 70)
    print("PREDICTION TEST COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()