import pandas as pd
import numpy as np
from pathlib import Path


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_DIR = BASE_DIR / "datasets" / "CICIDS2017"

OUTPUT_DIR = BASE_DIR / "datasets" / "processed"
OUTPUT_FILE = OUTPUT_DIR / "cicids2017_clean.csv"


# ---------------------------------------------------------
# Load dataset
# ---------------------------------------------------------

def load_dataset():
    csv_files = sorted(DATASET_DIR.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in {DATASET_DIR}"
        )

    print(f"Found {len(csv_files)} CSV files.")

    dataframes = []

    for file_path in csv_files:
        print(f"Loading: {file_path.name}")

        df = pd.read_csv(
            file_path,
            low_memory=False
        )

        print(f"  Rows: {len(df):,}")

        dataframes.append(df)

    print("\nCombining datasets...")

    combined = pd.concat(
        dataframes,
        ignore_index=True
    )

    print(f"Combined rows: {len(combined):,}")
    print(f"Columns: {len(combined.columns)}")

    return combined


# ---------------------------------------------------------
# Clean column names
# ---------------------------------------------------------

def clean_column_names(df):

    df.columns = (
        df.columns
        .str.strip()
        .str.replace(" ", "_")
        .str.replace("/", "_")
        .str.replace("-", "_")
    )

    return df


# ---------------------------------------------------------
# Clean infinite and missing values
# ---------------------------------------------------------

def clean_values(df):

    print("\nCleaning infinite values...")

    # Convert +inf and -inf to NaN
    df = df.replace(
        [np.inf, -np.inf],
        np.nan
    )

    print("Cleaning missing values...")

    # Count missing values before cleaning
    missing_before = df.isna().sum().sum()

    print(f"Missing values before cleaning: {missing_before:,}")

    # Remove rows containing missing values
    df = df.dropna()

    missing_after = df.isna().sum().sum()

    print(f"Missing values after cleaning: {missing_after:,}")

    return df


# ---------------------------------------------------------
# Clean labels
# ---------------------------------------------------------

def create_binary_label(df):

    print("\nCreating binary labels...")

    # Remove whitespace from labels
    df["Label"] = (
        df["Label"]
        .astype(str)
        .str.strip()
    )

    # BENIGN = 0
    # Everything else = 1
    df["Attack"] = (
        df["Label"]
        .str.upper()
        .ne("BENIGN")
        .astype(int)
    )

    print("\nBinary label distribution:")

    print(
        df["Attack"]
        .value_counts()
        .sort_index()
    )

    return df


# ---------------------------------------------------------
# Remove original label
# ---------------------------------------------------------

def prepare_features(df):

    # Keep Attack as our target.
    #
    # Label contains the original attack name.
    # We don't want the model seeing the answer directly.

    df = df.drop(columns=["Label"])

    return df


# ---------------------------------------------------------
# Save processed dataset
# ---------------------------------------------------------

def save_dataset(df):

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print("\nProcessed dataset saved to:")
    print(OUTPUT_FILE)


# ---------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------

def main():

    print("=" * 70)
    print("CICIDS2017 PREPROCESSING")
    print("=" * 70)

    # 1. Load
    df = load_dataset()

    # 2. Clean column names
    print("\nCleaning column names...")
    df = clean_column_names(df)

    # 3. Clean NaN and infinity
    df = clean_values(df)

    # 4. Create binary target
    df = create_binary_label(df)

    # 5. Remove original Label column
    df = prepare_features(df)

    # 6. Save
    save_dataset(df)

    print("\n" + "=" * 70)
    print("PREPROCESSING COMPLETE")
    print("=" * 70)

    print(f"Final rows: {len(df):,}")
    print(f"Final columns: {len(df.columns)}")


if __name__ == "__main__":
    main()