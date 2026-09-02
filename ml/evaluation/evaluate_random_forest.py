import pandas as pd
import joblib

from pathlib import Path
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    roc_auc_score
)


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "datasets" / "processed"
MODEL_DIR = BASE_DIR / "models"

TEST_FILE = DATA_DIR / "test_scaled.csv"
MODEL_FILE = MODEL_DIR / "random_forest.pkl"


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    print("=" * 70)
    print("RANDOM FOREST EVALUATION")
    print("=" * 70)

    # -----------------------------------------------------
    # Load test data
    # -----------------------------------------------------

    print("\nLoading test data...")

    test_df = pd.read_csv(
        TEST_FILE,
        low_memory=False
    )

    print(f"Test rows: {len(test_df):,}")

    # -----------------------------------------------------
    # Separate features and target
    # -----------------------------------------------------

    X_test = test_df.drop(columns=["Attack"])
    y_test = test_df["Attack"]

    # -----------------------------------------------------
    # Load model
    # -----------------------------------------------------

    print("\nLoading Random Forest model...")

    model = joblib.load(
        MODEL_FILE
    )

    # -----------------------------------------------------
    # Predictions
    # -----------------------------------------------------

    print("\nGenerating predictions...")

    y_pred = model.predict(X_test)

    # Probability of attack
    y_probability = model.predict_proba(X_test)[:, 1]

    # -----------------------------------------------------
    # Metrics
    # -----------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    precision = precision_score(
        y_test,
        y_pred,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        zero_division=0
    )

    roc_auc = roc_auc_score(
        y_test,
        y_probability
    )

    # -----------------------------------------------------
    # Results
    # -----------------------------------------------------

    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)

    print(f"\nAccuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print(f"ROC-AUC:   {roc_auc:.4f}")

    # -----------------------------------------------------
    # Classification report
    # -----------------------------------------------------

    print("\n" + "=" * 70)
    print("CLASSIFICATION REPORT")
    print("=" * 70)

    print(
        classification_report(
            y_test,
            y_pred,
            target_names=[
                "BENIGN",
                "ATTACK"
            ],
            zero_division=0
        )
    )

    # -----------------------------------------------------
    # Confusion matrix
    # -----------------------------------------------------

    print("=" * 70)
    print("CONFUSION MATRIX")
    print("=" * 70)

    cm = confusion_matrix(
        y_test,
        y_pred
    )

    print("\n                 Predicted")
    print("              BENIGN  ATTACK")
    print(
        f"Actual BENIGN  {cm[0][0]:7d}  {cm[0][1]:7d}"
    )
    print(
        f"Actual ATTACK  {cm[1][0]:7d}  {cm[1][1]:7d}"
    )

    print("\n" + "=" * 70)
    print("EVALUATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()