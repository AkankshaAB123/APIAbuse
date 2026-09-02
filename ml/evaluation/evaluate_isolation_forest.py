import pandas as pd
import joblib

from pathlib import Path
from sklearn.metrics import classification_report, confusion_matrix


# =========================================================
# PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

TEST_FILE = (
    BASE_DIR
    / "datasets"
    / "processed"
    / "test_scaled.csv"
)

MODEL_FILE = (
    BASE_DIR
    / "models"
    / "isolation_forest.pkl"
)


# =========================================================
# LOAD DATA
# =========================================================

print("=" * 70)
print("ISOLATION FOREST EVALUATION")
print("=" * 70)

print("\nLoading test data...")

df = pd.read_csv(TEST_FILE)

print(f"Test rows: {len(df)}")


# =========================================================
# SEPARATE FEATURES / LABEL
# =========================================================

X = df.drop(columns=["Attack"])
y = df["Attack"]


# =========================================================
# LOAD MODEL
# =========================================================

print("\nLoading Isolation Forest model...")

model = joblib.load(MODEL_FILE)


# =========================================================
# GENERATE PREDICTIONS
# =========================================================

print("\nGenerating anomaly predictions...")

predictions = model.predict(X)

# Isolation Forest:
#   1  = normal
#  -1  = anomaly
#
# Convert to:
#   0 = BENIGN / normal
#   1 = ATTACK / anomaly

predictions = (predictions == -1).astype(int)


# =========================================================
# RESULTS
# =========================================================

print("\n" + "=" * 70)
print("RESULTS")
print("=" * 70)

print("\nClassification Report:")

print(
    classification_report(
        y,
        predictions,
        target_names=["BENIGN", "ATTACK"]
    )
)


# =========================================================
# CONFUSION MATRIX
# =========================================================

print("=" * 70)
print("CONFUSION MATRIX")
print("=" * 70)

cm = confusion_matrix(y, predictions)

print()
print("                 Predicted")
print("              BENIGN  ATTACK")
print(
    f"Actual BENIGN  {cm[0][0]:6d}  {cm[0][1]:6d}"
)
print(
    f"Actual ATTACK  {cm[1][0]:6d}  {cm[1][1]:6d}"
)


# =========================================================
# ANOMALY DISTRIBUTION
# =========================================================

print("\n" + "=" * 70)
print("ANOMALY DISTRIBUTION")
print("=" * 70)

normal_count = (predictions == 0).sum()
anomaly_count = (predictions == 1).sum()

print(f"\nNormal:    {normal_count}")
print(f"Anomalous: {anomaly_count}")


print("\n" + "=" * 70)
print("ISOLATION FOREST EVALUATION COMPLETE")
print("=" * 70)