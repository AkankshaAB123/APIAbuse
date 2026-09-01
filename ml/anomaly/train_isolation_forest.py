import pandas as pd
import joblib

from pathlib import Path
from sklearn.ensemble import IsolationForest


# =========================================================
# PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

TRAIN_FILE = (
    BASE_DIR
    / "datasets"
    / "processed"
    / "train_scaled.csv"
)

MODEL_DIR = BASE_DIR / "models"

MODEL_FILE = MODEL_DIR / "isolation_forest.pkl"


# =========================================================
# SETTINGS
# =========================================================

CONTAMINATION = 0.01
RANDOM_STATE = 42


# =========================================================
# LOAD DATA
# =========================================================

print("=" * 70)
print("ISOLATION FOREST TRAINING")
print("=" * 70)

print("\nLoading training data...")

df = pd.read_csv(TRAIN_FILE)

print(f"Training rows: {len(df)}")
print(f"Training columns: {len(df.columns)}")


# =========================================================
# SEPARATE FEATURES AND LABEL
# =========================================================

print("\nSeparating features...")

X = df.drop(columns=["Attack"])
y = df["Attack"]


# =========================================================
# KEEP BENIGN TRAFFIC ONLY
# =========================================================

print("\nSelecting BENIGN traffic...")

X_benign = X[y == 0]

print(f"Total benign rows: {len(X_benign)}")
print(f"Features: {X_benign.shape[1]}")


# =========================================================
# CREATE MODEL
# =========================================================

print("\nCreating Isolation Forest...")

model = IsolationForest(
    n_estimators=200,
    contamination=CONTAMINATION,
    random_state=RANDOM_STATE,
    n_jobs=-1
)


# =========================================================
# TRAIN
# =========================================================

print("\nTraining model...")
print("This may take a while.")

model.fit(X_benign)

print("\nTraining complete!")


# =========================================================
# SAVE MODEL
# =========================================================

MODEL_DIR.mkdir(
    parents=True,
    exist_ok=True
)

joblib.dump(
    model,
    MODEL_FILE
)

print("\nModel saved to:")

print(MODEL_FILE)

print("\n" + "=" * 70)
print("ISOLATION FOREST TRAINING COMPLETE")
print("=" * 70)