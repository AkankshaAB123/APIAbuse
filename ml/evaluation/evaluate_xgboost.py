import pandas as pd
import joblib

from pathlib import Path
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix
)


BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "datasets" / "processed"
MODEL_DIR = BASE_DIR / "models"

TEST_FILE = DATA_DIR / "test_scaled.csv"
MODEL_FILE = MODEL_DIR / "xgboost.pkl"


def main():

    print("=" * 70)
    print("XGBOOST EVALUATION")
    print("=" * 70)

    print("\nLoading test data...")

    df = pd.read_csv(
        TEST_FILE,
        low_memory=False
    )

    print(f"Test rows: {len(df):,}")

    X = df.drop(columns=["Attack"])
    y = df["Attack"]

    print("\nLoading XGBoost model...")

    model = joblib.load(
        MODEL_FILE
    )

    print("\nGenerating predictions...")

    predictions = model.predict(X)

    probabilities = model.predict_proba(X)[:, 1]

    # -----------------------------------------------------
    # Metrics
    # -----------------------------------------------------

    accuracy = accuracy_score(
        y,
        predictions
    )

    precision = precision_score(
        y,
        predictions
    )

    recall = recall_score(
        y,
        predictions
    )

    f1 = f1_score(
        y,
        predictions
    )

    roc_auc = roc_auc_score(
        y,
        probabilities
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
            y,
            predictions,
            target_names=[
                "BENIGN",
                "ATTACK"
            ]
        )
    )

    # -----------------------------------------------------
    # Confusion matrix
    # -----------------------------------------------------

    matrix = confusion_matrix(
        y,
        predictions
    )

    print("=" * 70)
    print("CONFUSION MATRIX")
    print("=" * 70)

    print(
        """
                 Predicted
              BENIGN  ATTACK
Actual BENIGN   {:6d}  {:6d}
Actual ATTACK   {:6d}  {:6d}
""".format(
            matrix[0][0],
            matrix[0][1],
            matrix[1][0],
            matrix[1][1]
        )
    )

    print("=" * 70)
    print("EVALUATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()