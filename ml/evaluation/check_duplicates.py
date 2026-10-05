import pandas as pd
from pathlib import Path


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "datasets" / "processed"

TRAIN_FILE = DATA_DIR / "train.csv"
TEST_FILE = DATA_DIR / "test.csv"


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    print("=" * 70)
    print("TRAIN / TEST DUPLICATE CHECK")
    print("=" * 70)

    # -----------------------------------------------------
    # Load data
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
    # Remove target column
    # -----------------------------------------------------

    X_train = train_df.drop(columns=["Attack"])
    X_test = test_df.drop(columns=["Attack"])

    # -----------------------------------------------------
    # Duplicates inside each dataset
    # -----------------------------------------------------

    train_duplicates = X_train.duplicated().sum()
    test_duplicates = X_test.duplicated().sum()

    print("\nDuplicates within training set:")
    print(f"  {train_duplicates:,}")

    print("\nDuplicates within testing set:")
    print(f"  {test_duplicates:,}")

    # -----------------------------------------------------
    # Cross-dataset duplicates
    # -----------------------------------------------------

    print("\nChecking train/test overlap...")

    # Hash each row instead of comparing the entire
    # DataFrames directly.
    train_hashes = pd.util.hash_pandas_object(
        X_train,
        index=False
    )

    test_hashes = pd.util.hash_pandas_object(
        X_test,
        index=False
    )

    train_hash_set = set(train_hashes)

    overlap = sum(
        row_hash in train_hash_set
        for row_hash in test_hashes
    )

    print("\nExact train/test duplicate rows:")
    print(f"  {overlap:,}")

    overlap_percentage = (
        overlap / len(X_test)
    ) * 100

    print(
        f"  {overlap_percentage:.4f}% of test set"
    )

    # -----------------------------------------------------
    # Result
    # -----------------------------------------------------

    print("\n" + "=" * 70)
    print("DUPLICATE CHECK COMPLETE")
    print("=" * 70)

    if overlap == 0:
        print("\nNo exact train/test duplicates found.")
    else:
        print(
            "\nWARNING: Exact rows exist in both "
            "training and testing sets."
        )


if __name__ == "__main__":
    main()