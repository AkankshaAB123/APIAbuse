import sys
from pathlib import Path

import pandas as pd


# =========================================================
# ADD PROJECT ROOT TO PYTHON PATH
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(PROJECT_ROOT))


# =========================================================
# IMPORT ANOMALY DETECTOR
# =========================================================

from ml.api.anomaly_detector import detect_anomaly


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
# CALL ANOMALY INTERFACE
# =========================================================

print("\nCalling detect_anomaly(features)...")

result = detect_anomaly(features)


# =========================================================
# DISPLAY RESULT
# =========================================================

print("\nAnomaly result:")

print(result)


# =========================================================
# DISPLAY ACTUAL LABEL
# =========================================================

print("\nActual label:")

if actual_label == 1:
    print("ATTACK")
else:
    print("BENIGN")


# =========================================================
# COMPLETE
# =========================================================

print("\n==============================================")
print("ANOMALY PREDICTION TEST COMPLETE")
print("==============================================")