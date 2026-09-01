import pandas as pd
import numpy as np
import joblib

from pathlib import Path
from sklearn.preprocessing import StandardScaler


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "datasets" / "processed"
MODEL_DIR = BASE_DIR / "models"

TRAIN_FILE = DATA_DIR / "train.csv"
TEST_FILE = DATA_DIR / "test.csv"

TRAIN_OUTPUT = DATA_DIR / "train_scaled.csv"
TEST_OUTPUT = DATA_DIR / "test_scaled.csv"

SCALER_OUTPUT = MODEL_DIR / "scaler.pkl"


# ---------------------------------------------------------
# Clean numerical values
# ---------------------------------------------------------

def clean_features(df):

    # Convert infinite values to NaN
    df = df.replace(
        [np.inf, -np.inf],
        np.nan
    )

    # Replace remaining missing values
    # using the median of each column
    df = df.fillna(df.median(numeric_only=True))

    return df


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    print("=" * 70)
    print("FEATURE PREPARATION")
    print("=" * 70)

    # -----------------------------------------------------
    # Load
    # -----------------------------------------------------

    print("\nLoading training data...")

    train_df = pd.read_csv(
        TRAIN_FILE,
        low_memory=False
    )

    print("Loading testing data...")

    test_df = pd.read_csv(
        TEST_FILE,
        low_memory=False
    )

    print(f"\nTraining rows: {len(train_df):,}")
    print(f"Testing rows:  {len(test_df):,}")

    # -----------------------------------------------------
    # Separate features and target
    # -----------------------------------------------------

    X_train = train_df.drop(columns=["Attack"])
    y_train = train_df["Attack"]

    X_test = test_df.drop(columns=["Attack"])
    y_test = test_df["Attack"]

    # -----------------------------------------------------
    # Clean values
    # -----------------------------------------------------

    print("\nCleaning training features...")

    X_train = clean_features(X_train)

    print("Cleaning testing features...")

    X_test = clean_features(X_test)

    # -----------------------------------------------------
    # Make sure columns match
    # -----------------------------------------------------

    if list(X_train.columns) != list(X_test.columns):
        raise ValueError(
            "Training and testing feature columns do not match."
        )

    # -----------------------------------------------------
    # Scaling
    # -----------------------------------------------------

    print("\nFitting StandardScaler on training data...")

    scaler = StandardScaler()

    X_train_scaled = scaler.fit_transform(X_train)

    print("Transforming testing data...")

    X_test_scaled = scaler.transform(X_test)

    # -----------------------------------------------------
    # Convert back to DataFrame
    # -----------------------------------------------------

    X_train_scaled = pd.DataFrame(
        X_train_scaled,
        columns=X_train.columns
    )

    X_test_scaled = pd.DataFrame(
        X_test_scaled,
        columns=X_test.columns
    )

    # Add target back
    X_train_scaled["Attack"] = y_train.values
    X_test_scaled["Attack"] = y_test.values

    # -----------------------------------------------------
    # Save datasets
    # -----------------------------------------------------

    print("\nSaving scaled training data...")

    X_train_scaled.to_csv(
        TRAIN_OUTPUT,
        index=False
    )

    print("Saving scaled testing data...")

    X_test_scaled.to_csv(
        TEST_OUTPUT,
        index=False
    )

    # -----------------------------------------------------
    # Save scaler
    # -----------------------------------------------------

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    joblib.dump(
        scaler,
        SCALER_OUTPUT
    )

    # -----------------------------------------------------
    # Done
    # -----------------------------------------------------

    print("\n" + "=" * 70)
    print("FEATURE PREPARATION COMPLETE")
    print("=" * 70)

    print(f"\nTraining data:")
    print(TRAIN_OUTPUT)

    print(f"\nTesting data:")
    print(TEST_OUTPUT)

    print(f"\nScaler:")
    print(SCALER_OUTPUT)


if __name__ == "__main__":
    main()