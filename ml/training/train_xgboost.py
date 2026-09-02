import pandas as pd
import joblib

from pathlib import Path
from xgboost import XGBClassifier


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "datasets" / "processed"
MODEL_DIR = BASE_DIR / "models"

TRAIN_FILE = DATA_DIR / "train_scaled.csv"
MODEL_FILE = MODEL_DIR / "xgboost.pkl"


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    print("=" * 70)
    print("XGBOOST TRAINING")
    print("=" * 70)

    # -----------------------------------------------------
    # Load training data
    # -----------------------------------------------------

    print("\nLoading training data...")

    df = pd.read_csv(
        TRAIN_FILE,
        low_memory=False
    )

    print(f"Training rows: {len(df):,}")
    print(f"Training columns: {len(df.columns)}")

    # -----------------------------------------------------
    # Separate features and target
    # -----------------------------------------------------

    X = df.drop(columns=["Attack"])
    y = df["Attack"]

    print(f"\nFeature count: {X.shape[1]}")

    print("\nClass distribution:")
    print(y.value_counts())

    # -----------------------------------------------------
    # Create XGBoost model
    # -----------------------------------------------------

    print("\nCreating XGBoost model...")

    model = XGBClassifier(
        n_estimators=200,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="binary:logistic",
        eval_metric="logloss",
        tree_method="hist",
        n_jobs=-1,
        random_state=42
    )

    # -----------------------------------------------------
    # Train
    # -----------------------------------------------------

    print("\nTraining model...")
    print("This may take a while.")

    model.fit(X, y)

    print("\nTraining complete!")

    # -----------------------------------------------------
    # Save model
    # -----------------------------------------------------

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

    # -----------------------------------------------------
    # Feature importance
    # -----------------------------------------------------

    importance = pd.Series(
        model.feature_importances_,
        index=X.columns
    )

    importance = importance.sort_values(
        ascending=False
    )

    print("\nTop 15 important features:")

    print(
        importance.head(15)
    )

    print("\n" + "=" * 70)
    print("XGBOOST TRAINING COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()