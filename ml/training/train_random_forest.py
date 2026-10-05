import pandas as pd
import joblib

from pathlib import Path
from sklearn.ensemble import RandomForestClassifier


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "datasets" / "processed"
MODEL_DIR = BASE_DIR / "models"

TRAIN_FILE = DATA_DIR / "train_scaled.csv"
MODEL_FILE = MODEL_DIR / "random_forest.pkl"


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    print("=" * 70)
    print("RANDOM FOREST TRAINING")
    print("=" * 70)

    # -----------------------------------------------------
    # Load training data
    # -----------------------------------------------------

    print("\nLoading training data...")

    train_df = pd.read_csv(
        TRAIN_FILE,
        low_memory=False
    )

    print(f"Training rows: {len(train_df):,}")
    print(f"Training columns: {len(train_df.columns)}")

    # -----------------------------------------------------
    # Separate features and target
    # -----------------------------------------------------

    X_train = train_df.drop(columns=["Attack"])
    y_train = train_df["Attack"]

    print("\nFeature count:", X_train.shape[1])

    print("\nClass distribution:")

    print(y_train.value_counts())

    # -----------------------------------------------------
    # Create Random Forest
    # -----------------------------------------------------

    print("\nCreating Random Forest...")

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    # -----------------------------------------------------
    # Train
    # -----------------------------------------------------

    print("\nTraining model...")
    print("This may take a while.")

    model.fit(
        X_train,
        y_train
    )

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

    print("\nTop 15 important features:")

    importance = pd.Series(
        model.feature_importances_,
        index=X_train.columns
    )

    importance = importance.sort_values(
        ascending=False
    )

    print(importance.head(15))

    print("\n" + "=" * 70)
    print("RANDOM FOREST TRAINING COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()