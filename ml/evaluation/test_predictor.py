import sys
from pathlib import Path

import pandas as pd


# =========================================================
# ADD PROJECT ROOT TO PYTHON PATH
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(PROJECT_ROOT))


# =========================================================
# IMPORT PREDICTOR
# =========================================================

from ml.api.predictor import predict


# =========================================================
# LOAD TEST DATA
# =========================================================

TEST_FILE = (
    PROJECT_ROOT
    / "ml"
    / "datasets"
    / "processed"
    / "test_scaled.csv"
)

print("Loading test data...")

df = pd.read_csv(TEST_FILE)

print(f"Test rows: {len(df)}")


# =========================================================
# GET FIRST ROW
# =========================================================

row = df.iloc[0]

actual_label = row["Attack"]


# =========================================================
# PREPARE FEATURES
# =========================================================

features = row.drop("Attack").to_dict()


# =========================================================
# CALL PREDICTION INTERFACE
# =========================================================

print("\nCalling predict(features)...")

result = predict(features)


# =========================================================
# DISPLAY RESULT
# =========================================================

print("\nPrediction result:")

print(result)


print("\nActual label:")

if actual_label == 1:
    print("ATTACK")
else:
    print("BENIGN")