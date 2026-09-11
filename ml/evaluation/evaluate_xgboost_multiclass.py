import pandas as pd
import joblib
import numpy as np
import matplotlib.pyplot as plt

from sklearn.preprocessing import label_binarize

from sklearn.metrics import (
    roc_curve,
    auc,
    roc_auc_score,
    classification_report,
    confusion_matrix,
    accuracy_score
)

from pathlib import Path


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
# GENERATE CLASS PROBABILITIES
# =========================================================

print("\nGenerating class probabilities...")

y_score = model.predict_proba(X)

print(
    f"Probability matrix shape: {y_score.shape}"
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
# MULTICLASS ROC / AUC
# =========================================================

print("\n" + "=" * 70)
print("MULTICLASS ROC-AUC EVALUATION")
print("=" * 70)


# ---------------------------------------------------------
# Convert actual labels to encoded integers
# ---------------------------------------------------------

y_encoded = label_encoder.transform(y)


# ---------------------------------------------------------
# One-vs-Rest binary representation
# ---------------------------------------------------------

y_test_bin = label_binarize(
    y_encoded,
    classes=np.arange(
        len(label_encoder.classes_)
    )
)


# ---------------------------------------------------------
# Calculate ROC curve and AUC for every class
# ---------------------------------------------------------

fpr = {}
tpr = {}
roc_auc = {}

n_classes = len(
    label_encoder.classes_
)

for i in range(n_classes):

    fpr[i], tpr[i], _ = roc_curve(
        y_test_bin[:, i],
        y_score[:, i]
    )

    roc_auc[i] = auc(
        fpr[i],
        tpr[i]
    )


# =========================================================
# PRINT PER-CLASS AUC
# =========================================================

print("\nPER-CLASS ROC-AUC")
print("-" * 70)

for i, class_name in enumerate(
    label_encoder.classes_
):

    print(
        f"{class_name:<35} "
        f"AUC = {roc_auc[i]:.4f}"
    )


# =========================================================
# MICRO-AVERAGE ROC
# =========================================================

micro_fpr, micro_tpr, _ = roc_curve(
    y_test_bin.ravel(),
    y_score.ravel()
)

micro_auc = auc(
    micro_fpr,
    micro_tpr
)


# =========================================================
# MACRO-AVERAGE ROC
# =========================================================

all_fpr = np.unique(
    np.concatenate(
        [
            fpr[i]
            for i in range(n_classes)
        ]
    )
)

mean_tpr = np.zeros_like(
    all_fpr
)

for i in range(n_classes):

    mean_tpr += np.interp(
        all_fpr,
        fpr[i],
        tpr[i]
    )

mean_tpr /= n_classes

macro_auc = auc(
    all_fpr,
    mean_tpr
)


# =========================================================
# PRINT MICRO / MACRO AUC
# =========================================================

print("\n" + "-" * 70)

print(
    f"Micro-average AUC: {micro_auc:.4f}"
)

print(
    f"Macro-average AUC: {macro_auc:.4f}"
)


# =========================================================
# SAVE AUC RESULTS
# =========================================================

auc_results = []

for i, class_name in enumerate(
    label_encoder.classes_
):

    auc_results.append(
        {
            "Class": class_name,
            "AUC": roc_auc[i]
        }
    )


auc_results.append(
    {
        "Class": "Macro Average",
        "AUC": macro_auc
    }
)

auc_results.append(
    {
        "Class": "Micro Average",
        "AUC": micro_auc
    }
)


auc_df = pd.DataFrame(
    auc_results
)


AUC_FILE = (
    BASE_DIR
    / "xgboost_auc_results.csv"
)

auc_df.to_csv(
    AUC_FILE,
    index=False
)

print(
    f"\nAUC results saved to:"
)

print(
    AUC_FILE
)


# =========================================================
# PLOT MULTICLASS ROC CURVES
# =========================================================

print("\nGenerating ROC curve...")

plt.figure(
    figsize=(10, 8)
)


# ---------------------------------------------------------
# Plot each class
# ---------------------------------------------------------

for i, class_name in enumerate(
    label_encoder.classes_
):

    plt.plot(
        fpr[i],
        tpr[i],
        linewidth=1,
        label=(
            f"{class_name} "
            f"(AUC = {roc_auc[i]:.3f})"
        )
    )


# ---------------------------------------------------------
# Micro-average
# ---------------------------------------------------------

plt.plot(
    micro_fpr,
    micro_tpr,
    linewidth=3,
    label=(
        f"Micro-average "
        f"(AUC = {micro_auc:.3f})"
    )
)


# ---------------------------------------------------------
# Macro-average
# ---------------------------------------------------------

plt.plot(
    all_fpr,
    mean_tpr,
    linewidth=3,
    linestyle="--",
    label=(
        f"Macro-average "
        f"(AUC = {macro_auc:.3f})"
    )
)


# ---------------------------------------------------------
# Random classifier baseline
# ---------------------------------------------------------

plt.plot(
    [0, 1],
    [0, 1],
    linestyle="--",
    linewidth=1
)


# ---------------------------------------------------------
# Labels and title
# ---------------------------------------------------------

plt.xlabel(
    "False Positive Rate"
)

plt.ylabel(
    "True Positive Rate"
)

plt.title(
    "Multiclass ROC Curve - XGBoost"
)


plt.legend(
    loc="lower right",
    fontsize=7
)

plt.grid(
    True,
    alpha=0.3
)

plt.tight_layout()


# =========================================================
# SAVE ROC FIGURE
# =========================================================

ROC_FILE = (
    BASE_DIR
    / "xgboost_multiclass_roc.png"
)

plt.savefig(
    ROC_FILE,
    dpi=300,
    bbox_inches="tight"
)

print(
    f"\nROC curve saved to:"
)

print(
    ROC_FILE
)


plt.show()


# =========================================================
# COMPLETE
# =========================================================

print("\n" + "=" * 70)
print("XGBOOST MULTICLASS EVALUATION COMPLETE")
print("=" * 70)