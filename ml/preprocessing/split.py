import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "datasets" / "processed"

INPUT_FILE = DATA_DIR / "cicids2017_clean.csv"

TRAIN_FILE = DATA_DIR / "train.csv"
TEST_FILE = DATA_DIR / "test.csv"


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    print("=" * 70)
    print("DUPLICATE-SAFE TRAIN / TEST SPLIT")
    print("=" * 70)

    # -----------------------------------------------------
    # Load dataset
    # -----------------------------------------------------

    print("\nLoading dataset...")

    df = pd.read_csv(
        INPUT_FILE,
        low_memory=False
    )

    print(f"Total rows: {len(df):,}")

    # -----------------------------------------------------
    # Separate target
    # -----------------------------------------------------

    target = "Attack"

    X = df.drop(columns=[target])
    y = df[target]

    # -----------------------------------------------------
    # Create a unique ID for every feature row
    # -----------------------------------------------------

    print("\nGrouping identical feature rows...")

    # factorize assigns the same group number to identical
    # feature rows.
    group_id = pd.util.hash_pandas_object(
        X,
        index=False
    )

    df["_group_id"] = group_id

    # -----------------------------------------------------
    # Create one row per unique feature group
    # -----------------------------------------------------

    groups = (
        df.groupby("_group_id")["Attack"]
        .first()
        .reset_index()
    )

    print(
        f"Unique feature groups: {len(groups):,}"
    )

    # -----------------------------------------------------
    # Split GROUPS instead of individual rows
    # -----------------------------------------------------

    print("\nSplitting groups...")

    train_groups, test_groups = train_test_split(
        groups,
        test_size=0.20,
        random_state=42,
        stratify=groups["Attack"]
    )

    train_group_ids = set(
        train_groups["_group_id"]
    )

    test_group_ids = set(
        test_groups["_group_id"]
    )

    # -----------------------------------------------------
    # Build train/test datasets
    # -----------------------------------------------------

    train_df = df[
        df["_group_id"].isin(train_group_ids)
    ].copy()

    test_df = df[
        df["_group_id"].isin(test_group_ids)
    ].copy()

    # Remove temporary column
    train_df.drop(
        columns=["_group_id"],
        inplace=True
    )

    test_df.drop(
        columns=["_group_id"],
        inplace=True
    )

    # -----------------------------------------------------
    # Shuffle
    # -----------------------------------------------------

    train_df = train_df.sample(
        frac=1,
        random_state=42
    ).reset_index(drop=True)

    test_df = test_df.sample(
        frac=1,
        random_state=42
    ).reset_index(drop=True)

    # -----------------------------------------------------
    # Save
    # -----------------------------------------------------

    print("\nSaving training data...")

    train_df.to_csv(
        TRAIN_FILE,
        index=False
    )

    print("Saving testing data...")

    test_df.to_csv(
        TEST_FILE,
        index=False
    )

    # -----------------------------------------------------
    # Display results
    # -----------------------------------------------------

    print("\n" + "=" * 70)
    print("SPLIT RESULTS")
    print("=" * 70)

    print(
        f"\nTraining rows: {len(train_df):,}"
    )

    print(
        f"Testing rows:  {len(test_df):,}"
    )

    print("\nTraining class distribution:")

    print(
        train_df["Attack"]
        .value_counts()
    )

    print("\nTesting class distribution:")

    print(
        test_df["Attack"]
        .value_counts()
    )

    # -----------------------------------------------------
    # Verify no group overlap
    # -----------------------------------------------------

    train_hashes = set(
        pd.util.hash_pandas_object(
            train_df.drop(columns=["Attack"]),
            index=False
        )
    )

    test_hashes = set(
        pd.util.hash_pandas_object(
            test_df.drop(columns=["Attack"]),
            index=False
        )
    )

    overlap = train_hashes.intersection(
        test_hashes
    )

    print("\nExact train/test duplicate rows:")

    print(
        f"  {len(overlap):,}"
    )

    # -----------------------------------------------------
    # Done
    # -----------------------------------------------------

    print("\n" + "=" * 70)

    if len(overlap) == 0:
        print("NO TRAIN/TEST DUPLICATE OVERLAP")
    else:
        print("WARNING: DUPLICATE OVERLAP DETECTED")

    print("=" * 70)


if __name__ == "__main__":
    main()