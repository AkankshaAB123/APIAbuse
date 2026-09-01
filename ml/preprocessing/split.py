import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    BASE_DIR
    / "datasets"
    / "processed"
    / "cicids2017_clean.csv"
)

OUTPUT_DIR = (
    BASE_DIR
    / "datasets"
    / "processed"
)


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    print("=" * 70)
    print("CICIDS2017 TRAIN / TEST SPLIT")
    print("=" * 70)

    # Load processed dataset
    print("\nLoading processed dataset...")

    df = pd.read_csv(
        INPUT_FILE,
        low_memory=False
    )

    print(f"Total rows: {len(df):,}")
    print(f"Total columns: {len(df.columns)}")

    # Separate features and target
    X = df.drop(columns=["Attack"])
    y = df["Attack"]

    print("\nOriginal class distribution:")
    print(y.value_counts())

    # -----------------------------------------------------
    # Train / Test split
    # -----------------------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print("\nSplit complete.")

    print(f"Training samples: {len(X_train):,}")
    print(f"Testing samples:  {len(X_test):,}")

    print("\nTraining class distribution:")
    print(y_train.value_counts())

    print("\nTesting class distribution:")
    print(y_test.value_counts())

    # -----------------------------------------------------
    # Save
    # -----------------------------------------------------

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    train_df = X_train.copy()
    train_df["Attack"] = y_train.values

    test_df = X_test.copy()
    test_df["Attack"] = y_test.values

    train_file = OUTPUT_DIR / "train.csv"
    test_file = OUTPUT_DIR / "test.csv"

    print("\nSaving training data...")

    train_df.to_csv(
        train_file,
        index=False
    )

    print("Saving testing data...")

    test_df.to_csv(
        test_file,
        index=False
    )

    print("\nSaved:")
    print(train_file)
    print(test_file)

    print("\n" + "=" * 70)
    print("SPLIT COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()