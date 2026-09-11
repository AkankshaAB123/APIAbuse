import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt

from pathlib import Path

from sklearn.ensemble import IsolationForest

from sklearn.metrics import (
    roc_auc_score,
    roc_curve,
    classification_report,
    confusion_matrix,
    accuracy_score
)

from sklearn.model_selection import train_test_split


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

ROC_FILE = (
    BASE_DIR
    / "models"
    / "isolation_forest_roc.png"
)


# =========================================================
# SETTINGS
# =========================================================

RANDOM_STATE = 42

VALIDATION_SIZE = 0.20

# Keep this low to prevent excessive RAM usage.
# Increase to 4 if your computer has enough RAM.
N_JOBS = 2


# =========================================================
# START
# =========================================================

print("=" * 70)
print("ISOLATION FOREST HYPERPARAMETER TUNING")
print("=" * 70)


# =========================================================
# LOAD TRAINING DATA
# =========================================================

print("\nLoading training data...")

train_df = pd.read_csv(
    TRAIN_FILE,
    low_memory=False
)

print(
    f"Training rows: {len(train_df):,}"
)


# =========================================================
# LOAD TEST DATA
# =========================================================

print("\nLoading testing data...")

test_df = pd.read_csv(
    TEST_FILE,
    low_memory=False
)

print(
    f"Testing rows: {len(test_df):,}"
)


# =========================================================
# SEPARATE FEATURES AND LABELS
# =========================================================

print("\nSeparating features and labels...")


if "Attack" not in train_df.columns:
    raise ValueError(
        "Training dataset must contain an 'Attack' column."
    )

if "Attack" not in test_df.columns:
    raise ValueError(
        "Testing dataset must contain an 'Attack' column."
    )


X_train_full = train_df.drop(
    columns=["Attack"]
)

y_train_full = train_df["Attack"].astype(int)


X_test = test_df.drop(
    columns=["Attack"]
)

y_test = test_df["Attack"].astype(int)


print(
    f"Number of features: {X_train_full.shape[1]}"
)

print(
    f"Training attacks: {(y_train_full == 1).sum():,}"
)

print(
    f"Training benign: {(y_train_full == 0).sum():,}"
)

print(
    f"Testing attacks: {(y_test == 1).sum():,}"
)

print(
    f"Testing benign: {(y_test == 0).sum():,}"
)


# =========================================================
# REDUCE MEMORY USAGE
# =========================================================

print("\nConverting feature data to float32...")

X_train_full = X_train_full.astype(
    np.float32
)

X_test = X_test.astype(
    np.float32
)


# =========================================================
# TRAIN / VALIDATION SPLIT
# =========================================================

print("\nCreating validation split...")

X_train, X_validation, y_train, y_validation = train_test_split(
    X_train_full,
    y_train_full,
    test_size=VALIDATION_SIZE,
    random_state=RANDOM_STATE,
    stratify=y_train_full
)

print(
    f"Training rows:   {len(X_train):,}"
)

print(
    f"Validation rows: {len(X_validation):,}"
)


# =========================================================
# HYPERPARAMETER CONFIGURATIONS
# =========================================================

configs = [

    {
        "n_estimators": 300,
        "max_samples": 256,
        "max_features": 1.0
    },

    {
        "n_estimators": 500,
        "max_samples": 256,
        "max_features": 1.0
    },

    {
        "n_estimators": 750,
        "max_samples": 256,
        "max_features": 1.0
    },

    {
        "n_estimators": 500,
        "max_samples": 512,
        "max_features": 1.0
    },

    {
        "n_estimators": 750,
        "max_samples": 512,
        "max_features": 1.0
    },

    {
        "n_estimators": 500,
        "max_samples": 1024,
        "max_features": 1.0
    },

    {
        "n_estimators": 750,
        "max_samples": 1024,
        "max_features": 1.0
    },

    {
        "n_estimators": 500,
        "max_samples": 256,
        "max_features": 0.8
    },

    {
        "n_estimators": 750,
        "max_samples": 256,
        "max_features": 0.8
    },

    {
        "n_estimators": 500,
        "max_samples": 512,
        "max_features": 0.8
    }
]


# =========================================================
# HYPERPARAMETER SEARCH
# =========================================================

print("\n" + "=" * 70)
print("TESTING CONFIGURATIONS")
print("=" * 70)


results = []

best_auc = -1

best_config = None


for i, config in enumerate(
    configs,
    start=1
):

    print("\n" + "-" * 70)

    print(
        f"Configuration {i}/{len(configs)}"
    )

    print(
        f"n_estimators = {config['n_estimators']}"
    )

    print(
        f"max_samples  = {config['max_samples']}"
    )

    print(
        f"max_features = {config['max_features']}"
    )


    # -----------------------------------------------------
    # CREATE MODEL
    # -----------------------------------------------------

    model = IsolationForest(

        n_estimators=config[
            "n_estimators"
        ],

        max_samples=config[
            "max_samples"
        ],

        max_features=config[
            "max_features"
        ],

        contamination="auto",

        random_state=RANDOM_STATE,

        n_jobs=N_JOBS
    )


    # -----------------------------------------------------
    # TRAIN
    # -----------------------------------------------------

    print("\nTraining model...")

    model.fit(
        X_train
    )


    # -----------------------------------------------------
    # ANOMALY SCORE
    # -----------------------------------------------------

    print(
        "Generating validation anomaly scores..."
    )

    validation_scores = (
        -model.decision_function(
            X_validation
        )
    )


    # -----------------------------------------------------
    # ROC-AUC
    # -----------------------------------------------------

    auc_score = roc_auc_score(
        y_validation,
        validation_scores
    )


    print(
        f"Validation ROC-AUC: {auc_score:.4f}"
    )


    # -----------------------------------------------------
    # SAVE RESULT
    # -----------------------------------------------------

    results.append({

        "configuration": i,

        "n_estimators":
            config["n_estimators"],

        "max_samples":
            config["max_samples"],

        "max_features":
            config["max_features"],

        "roc_auc":
            auc_score
    })


    # -----------------------------------------------------
    # CHECK BEST
    # -----------------------------------------------------

    if auc_score > best_auc:

        best_auc = auc_score

        best_config = config.copy()


    # -----------------------------------------------------
    # DELETE MODEL
    # -----------------------------------------------------

    del model

    del validation_scores


# =========================================================
# RESULTS TABLE
# =========================================================

results_df = pd.DataFrame(
    results
)

results_df = results_df.sort_values(
    by="roc_auc",
    ascending=False
)


print("\n" + "=" * 70)
print("HYPERPARAMETER RESULTS")
print("=" * 70)

print()

print(
    results_df.to_string(
        index=False
    )
)


# =========================================================
# BEST CONFIGURATION
# =========================================================

print("\n" + "=" * 70)

print(
    f"BEST VALIDATION ROC-AUC: {best_auc:.4f}"
)

print("=" * 70)

print("\nBEST CONFIGURATION:")

print(
    f"n_estimators = "
    f"{best_config['n_estimators']}"
)

print(
    f"max_samples  = "
    f"{best_config['max_samples']}"
)

print(
    f"max_features = "
    f"{best_config['max_features']}"
)


# =========================================================
# TRAIN FINAL MODEL
# =========================================================

print("\n" + "=" * 70)
print("TRAINING FINAL MODEL")
print("=" * 70)

print(
    "\nUsing the complete training dataset..."
)


final_model = IsolationForest(

    n_estimators=
        best_config["n_estimators"],

    max_samples=
        best_config["max_samples"],

    max_features=
        best_config["max_features"],

    contamination="auto",

    random_state=RANDOM_STATE,

    n_jobs=N_JOBS
)


final_model.fit(
    X_train_full
)


print(
    "\nFinal model trained successfully."
)


# =========================================================
# TEST ANOMALY SCORES
# =========================================================

print(
    "\nGenerating test anomaly scores..."
)


test_scores = (
    -final_model.decision_function(
        X_test
    )
)


# =========================================================
# TEST ROC-AUC
# =========================================================

test_auc = roc_auc_score(
    y_test,
    test_scores
)


print("\n" + "=" * 70)
print("FINAL TEST RESULT")
print("=" * 70)

print(
    f"\nTest ROC-AUC: {test_auc:.4f}"
)


# =========================================================
# ROC CURVE
# =========================================================

print(
    "\nGenerating ROC curve..."
)


fpr, tpr, thresholds = roc_curve(
    y_test,
    test_scores
)


plt.figure(
    figsize=(10, 7)
)


plt.plot(
    fpr,
    tpr,
    linewidth=2,
    label=(
        f"Isolation Forest "
        f"(AUC = {test_auc:.3f})"
    )
)


plt.plot(
    [0, 1],
    [0, 1],
    linestyle="--",
    label="Random Classifier"
)


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
    alpha=0.3
)


plt.tight_layout()


ROC_FILE.parent.mkdir(
    parents=True,
    exist_ok=True
)


plt.savefig(
    ROC_FILE,
    dpi=300,
    bbox_inches="tight"
)


plt.show()


print(
    f"\nROC curve saved to:\n{ROC_FILE}"
)


# =========================================================
# DEFAULT ISOLATION FOREST PREDICTIONS
# =========================================================

print(
    "\nGenerating default predictions..."
)


predictions_raw = (
    final_model.predict(
        X_test
    )
)


# Isolation Forest:
#
#  1  = normal
# -1  = anomaly
#
# Convert:
#
#  0 = BENIGN
#  1 = ATTACK


predictions = (
    predictions_raw == -1
).astype(int)


# =========================================================
# ACCURACY
# =========================================================

accuracy = accuracy_score(
    y_test,
    predictions
)


print("\n" + "=" * 70)
print("CLASSIFICATION RESULTS")
print("=" * 70)


print(
    f"\nAccuracy: {accuracy:.4f}"
)


# =========================================================
# CLASSIFICATION REPORT
# =========================================================

print(
    "\nClassification Report:"
)


print(
    classification_report(
        y_test,
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

print("\n" + "=" * 70)
print("CONFUSION MATRIX")
print("=" * 70)


cm = confusion_matrix(
    y_test,
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
    f"Actual BENIGN  "
    f"{cm[0][0]:7d} "
    f"{cm[0][1]:7d}"
)

print(
    f"Actual ATTACK  "
    f"{cm[1][0]:7d} "
    f"{cm[1][1]:7d}"
)


# =========================================================
# ANOMALY DISTRIBUTION
# =========================================================

normal_count = (
    predictions == 0
).sum()


anomaly_count = (
    predictions == 1
).sum()


print("\n" + "=" * 70)
print("ANOMALY DISTRIBUTION")
print("=" * 70)


print(
    f"\nNormal:    {normal_count:,}"
)

print(
    f"Anomalous: {anomaly_count:,}"
)


# =========================================================
# SAVE FINAL MODEL
# =========================================================

print("\n" + "=" * 70)
print("SAVING FINAL MODEL")
print("=" * 70)


MODEL_FILE.parent.mkdir(
    parents=True,
    exist_ok=True
)


joblib.dump(
    final_model,
    MODEL_FILE
)


print(
    f"\nModel saved to:\n{MODEL_FILE}"
)


# =========================================================
# FINAL SUMMARY
# =========================================================

print("\n" + "=" * 70)
print("ISOLATION FOREST TRAINING COMPLETE")
print("=" * 70)


print(
    f"\nBest validation AUC: "
    f"{best_auc:.4f}"
)


print(
    f"Final test AUC:       "
    f"{test_auc:.4f}"
)


print(
    f"Final accuracy:       "
    f"{accuracy:.4f}"
)


print(
    f"\nModel:"
    f"\n{MODEL_FILE}"
)


print(
    f"\nROC curve:"
    f"\n{ROC_FILE}"
)


print("\n" + "=" * 70)