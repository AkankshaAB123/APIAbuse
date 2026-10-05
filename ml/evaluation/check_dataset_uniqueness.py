import pandas as pd
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

DATA_FILE = (
    BASE_DIR
    / "datasets"
    / "processed"
    / "cicids2017_clean.csv"
)


def main():

    print("=" * 70)
    print("DATASET UNIQUENESS CHECK")
    print("=" * 70)

    print("\nLoading dataset...")

    df = pd.read_csv(
        DATA_FILE,
        low_memory=False
    )

    print(f"\nTotal rows: {len(df):,}")
    print(f"Total columns: {len(df.columns):,}")

    # Remove target
    X = df.drop(columns=["Attack"])

    print("\nChecking unique feature rows...")

    unique_rows = X.drop_duplicates().shape[0]

    duplicate_rows = len(X) - unique_rows

    print(f"\nUnique feature rows:    {unique_rows:,}")
    print(f"Duplicate feature rows: {duplicate_rows:,}")

    percentage = (
        duplicate_rows / len(X)
    ) * 100

    print(
        f"Duplicate percentage:   {percentage:.2f}%"
    )

    print("\n" + "=" * 70)
    print("UNIQUENESS CHECK COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()