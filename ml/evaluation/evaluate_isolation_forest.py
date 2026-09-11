import pandas as pd
import joblib
import matplotlib.pyplot as plt

from pathlib import Path

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_curve,
    auc,
    roc_auc_score
)


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

ROC_OUTPUT = (
    BASE_DIR
    / "isolation_forest_roc.png"
)


# =========================================================
# START
# =========================================================

print("=" * 70)
print("ISOLATION FOREST EVALUATION")
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


# =========================================================
# SEPARATE FEATURES / LABEL
# =========================================================

print("\nSeparating features and labels...")

X = df.drop(
    columns=["Attack"]
)

y = df["Attack"]


# =========================================================
# LOAD MODEL
# =========================================================

print("\nLoading Isolation Forest model...")

model = joblib.load(
    MODEL_FILE
)

print(
    "Isolation Forest model loaded successfully."
)


# =========================================================
# GENERATE PREDICTIONS
# =========================================================

print("\nGenerating anomaly predictions...")

predictions = model.predict(
    X
)

# Isolation Forest:
#
#  1  = normal
# -1  = anomaly
#
# Convert to:
#
#  0 = BENIGN / normal
#  1 = ATTACK / anomaly

predictions = (
    predictions == -1
).astype(int)


# =========================================================
# RESULTS
# =========================================================

print("\n" + "=" * 70)
print("RESULTS")
print("=" * 70)


# =========================================================
# CLASSIFICATION REPORT
# =========================================================

print("\nClassification Report:")

print(
    classification_report(
        y,
        predictions,
        target_names=[
            "BENIGN",
            "ATTACK"
        ],
        zero_division=0
    )
)


# =========================================================
# CONFUSION MATRIX
# =========================================================

print("=" * 70)
print("CONFUSION MATRIX")
print("=" * 70)

cm = confusion_matrix(
    y,
    predictions
)

print()

print(
    "                 Predicted"
)

print(
    "              BENIGN  ATTACK"
)

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

normal_count = (
    predictions == 0
).sum()

anomaly_count = (
    predictions == 1
).sum()

print(
    f"\nNormal:    {normal_count:,}"
)

print(
    f"Anomalous: {anomaly_count:,}"
)


# =========================================================
# ROC / AUC
# =========================================================

print("\n" + "=" * 70)
print("ROC-AUC EVALUATION")
print("=" * 70)


# Isolation Forest's decision_function:
#
# Higher value = more normal
# Lower value  = more anomalous
#
# ROC requires:
# Higher score = more likely to be ATTACK
#
# Therefore negate the decision function.

print(
    "\nGenerating anomaly scores..."
)

anomaly_scores = (
    -model.decision_function(X)
)


# =========================================================
# CALCULATE ROC CURVE
# =========================================================

print(
    "Calculating ROC curve..."
)

fpr, tpr, thresholds = roc_curve(
    y,
    anomaly_scores
)


# =========================================================
# CALCULATE AUC
# =========================================================

roc_auc = auc(
    fpr,
    tpr
)

# Same calculation using sklearn
roc_auc_check = roc_auc_score(
    y,
    anomaly_scores
)

print(
    f"\nROC-AUC: {roc_auc:.4f}"
)

print(
    f"ROC-AUC verification: {roc_auc_check:.4f}"
)


# =========================================================
# PLOT ROC CURVE
# =========================================================

print(
    "\nGenerating ROC curve figure..."
)

plt.figure(
    figsize=(8, 6)
)


# Isolation Forest ROC
plt.plot(
    fpr,
    tpr,
    linewidth=2,
    label=(
        f"Isolation Forest "
        f"(AUC = {roc_auc:.3f})"
    )
)


# Random classifier baseline
plt.plot(
    [0, 1],
    [0, 1],
    linestyle="--",
    linewidth=1,
    label="Random Classifier"
)


# =========================================================
# GRAPH LABELS
# =========================================================

plt.xlabel(
    "False Positive Rate"
)

plt.ylabel(
    "True Positive Rate"
)

plt.title(
    "ROC Curve - Isolation Forest"
)

plt.legend(
    loc="lower right"
)

plt.grid(
    True,
    alpha=0.3
)

plt.tight_layout()


# =========================================================
# SAVE GRAPH
# =========================================================

plt.savefig(
    ROC_OUTPUT,
    dpi=300,
    bbox_inches="tight"
)

print(
    f"\nROC curve saved to:"
)

print(
    ROC_OUTPUT
)


# =========================================================
# DISPLAY GRAPH
# =========================================================

plt.show()


# =========================================================
# COMPLETE
# =========================================================

print(
    "\n" + "=" * 70
)

print(
    "ISOLATION FOREST EVALUATION COMPLETE"
)

print(
    "=" * 70
)