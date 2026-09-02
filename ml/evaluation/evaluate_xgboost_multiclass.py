import pandas as pd
import joblib

from pathlib import Path

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score
)


# =========================================================
# PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

TEST_FILE = (
    BASE_DIR
    / "datasets"
    / "processed"
    / "multiclass_test_scaled.csv"
)

MODEL_FILE = (
    BASE_DIR
    / "models"
    / "xgboost_multiclass.pkl"
)

ENCODER_FILE = (
    BASE_DIR
    / "models"
    / "multiclass_label_encoder.pkl"
)


# =========================================================
# START
# =========================================================

print("=" * 70)
print("XGBOOST MULTICLASS EVALUATION")
print("=" * 70)


# =========================================================
# LOAD TEST DATA
# =========================================================

print("\nLoading test data...")

df = pd.read_csv(
    TEST_FILE,
    low_memory=False
)

print(
    f"Test rows: {len(df):,}"
)

print(
    f"Test columns: {len(df.columns)}"
)


# =========================================================
# LOAD MODEL
# =========================================================

print("\nLoading XGBoost multiclass model...")

model = joblib.load(
    MODEL_FILE
)

print(
    "XGBoost multiclass model loaded successfully."
)


# =========================================================
# LOAD LABEL ENCODER
# =========================================================

print("\nLoading label encoder...")

label_encoder = joblib.load(
    ENCODER_FILE
)

print(
    "Label encoder loaded successfully."
)


# =========================================================
# SEPARATE FEATURES AND LABEL
# =========================================================

print("\nSeparating features and labels...")

X = df.drop(
    columns=["Label"]
)

y = df["Label"]


# =========================================================
# PREDICT
# =========================================================

print("\nGenerating predictions...")

predicted_encoded = model.predict(
    X
)

predicted_labels = (
    label_encoder.inverse_transform(
        predicted_encoded.astype(int)
    )
)


# =========================================================
# ACCURACY
# =========================================================

accuracy = accuracy_score(
    y,
    predicted_labels
)


# =========================================================
# RESULTS
# =========================================================

print("\n" + "=" * 70)
print("RESULTS")
print("=" * 70)

print(
    f"\nOverall Accuracy: {accuracy:.4f}"
)


# =========================================================
# CLASSIFICATION REPORT
# =========================================================

print("\n" + "=" * 70)
print("CLASSIFICATION REPORT")
print("=" * 70)

print(
    classification_report(
        y,
        predicted_labels,
        labels=label_encoder.classes_,
        zero_division=0
    )
)


# =========================================================
# CONFUSION MATRIX
# =========================================================

print("\n" + "=" * 70)
print("CONFUSION MATRIX")
print("=" * 70)

cm = confusion_matrix(
    y,
    predicted_labels,
    labels=label_encoder.classes_
)

cm_df = pd.DataFrame(
    cm,
    index=label_encoder.classes_,
    columns=label_encoder.classes_
)

print(cm_df)


# =========================================================
# COMPLETE
# =========================================================

print("\n" + "=" * 70)
print("XGBOOST MULTICLASS EVALUATION COMPLETE")
print("=" * 70)