import pandas as pd
import numpy as np
import joblib

from pathlib import Path
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split


# =========================================================
# PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

# CHANGE THIS if your original CICIDS2017 CSVs are somewhere else
RAW_DATA_DIR = BASE_DIR / "datasets" / "raw" / "CICIDS2017"

OUTPUT_DIR = BASE_DIR / "datasets" / "processed"

TRAIN_OUTPUT = OUTPUT_DIR / "multiclass_train_scaled.csv"
TEST_OUTPUT = OUTPUT_DIR / "multiclass_test_scaled.csv"

SCALER_OUTPUT = BASE_DIR / "models" / "multiclass_scaler.pkl"


# =========================================================
# SETTINGS
# =========================================================

RANDOM_STATE = 42
TEST_SIZE = 0.20


# =========================================================
# LOAD ORIGINAL CICIDS FILES
# =========================================================

def load_original_data():

    print("=" * 70)
    print("MULTICLASS DATA PREPARATION")
    print("=" * 70)

    print("\nLooking for original CICIDS2017 CSV files...")

    csv_files = list(RAW_DATA_DIR.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in:\n{RAW_DATA_DIR}\n\n"
            "Put the original CICIDS2017 CSV files in this directory."
        )

    print(f"\nFound {len(csv_files)} CSV files:")

    for file in csv_files:
        print(f"  - {file.name}")

    frames = []

    for file in csv_files:

        print(f"\nLoading: {file.name}")

        df = pd.read_csv(
            file,
            low_memory=False
        )

        print(f"Rows: {len(df):,}")

        frames.append(df)

    print("\nCombining datasets...")

    combined = pd.concat(
        frames,
        ignore_index=True
    )

    print(
        f"Combined rows: {len(combined):,}"
    )

    return combined


# =========================================================
# CLEAN COLUMN NAMES
# =========================================================

def clean_column_names(df):

    df.columns = (
        df.columns
        .str.strip()
    )

    return df


# =========================================================
# CLEAN LABELS
# =========================================================

def clean_labels(df):

    if "Label" not in df.columns:
        raise ValueError(
            "Original 'Label' column was not found."
        )

    print("\nCleaning attack labels...")

    df["Label"] = (
        df["Label"]
        .astype(str)
        .str.strip()
    )

    # Remove rows with invalid labels
    df = df[
        df["Label"].notna()
    ]

    print("\nAttack type distribution:")

    print(
        df["Label"]
        .value_counts()
    )

    return df


# =========================================================
# CLEAN FEATURES
# =========================================================

def clean_features(X):

    print("\nCleaning numerical features...")

    # Convert everything to numeric
    for column in X.columns:

        X[column] = pd.to_numeric(
            X[column],
            errors="coerce"
        )

    # Replace infinity
    X = X.replace(
        [np.inf, -np.inf],
        np.nan
    )

    # Fill missing values using training-independent
    # column medians before splitting
    X = X.fillna(
        X.median()
    )

    return X


# =========================================================
# MAIN
# =========================================================

def main():

    # -----------------------------------------------------
    # Load
    # -----------------------------------------------------

    df = load_original_data()

    df = clean_column_names(df)

    df = clean_labels(df)

    # -----------------------------------------------------
    # Features
    # -----------------------------------------------------

    # Remove label
    X = df.drop(
        columns=["Label"]
    )

    y = df["Label"]

    # -----------------------------------------------------
    # Keep only numerical CICIDS features
    # -----------------------------------------------------

    X = clean_features(X)

    # Make sure all columns are numeric
    X = X.select_dtypes(
        include=[np.number]
    )

    print(
        f"\nFeature count: {X.shape[1]}"
    )

    if X.shape[1] != 78:

        print(
            "\nWARNING:"
        )

        print(
            f"Expected 78 features, "
            f"found {X.shape[1]}."
        )

        print(
            "\nFeatures:"
        )

        for column in X.columns:
            print(column)

    # -----------------------------------------------------
    # Remove completely invalid rows
    # -----------------------------------------------------

    valid_rows = X.notna().all(axis=1)

    X = X.loc[valid_rows]
    y = y.loc[valid_rows]

    # -----------------------------------------------------
    # Split
    # -----------------------------------------------------

    print("\nSplitting dataset...")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y
    )

    print(
        f"Training rows: {len(X_train):,}"
    )

    print(
        f"Testing rows: {len(X_test):,}"
    )

    # -----------------------------------------------------
    # Scaling
    # -----------------------------------------------------

    print(
        "\nFitting StandardScaler "
        "on training data..."
    )

    scaler = StandardScaler()

    X_train_scaled = scaler.fit_transform(
        X_train
    )

    print(
        "Transforming testing data..."
    )

    X_test_scaled = scaler.transform(
        X_test
    )

    # -----------------------------------------------------
    # Convert back to DataFrame
    # -----------------------------------------------------

    X_train_scaled = pd.DataFrame(
        X_train_scaled,
        columns=X_train.columns,
        index=X_train.index
    )

    X_test_scaled = pd.DataFrame(
        X_test_scaled,
        columns=X_test.columns,
        index=X_test.index
    )

    # -----------------------------------------------------
    # Add original attack labels
    # -----------------------------------------------------

    X_train_scaled["Label"] = y_train.values

    X_test_scaled["Label"] = y_test.values

    # -----------------------------------------------------
    # Create directories
    # -----------------------------------------------------

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    SCALER_OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # -----------------------------------------------------
    # Save
    # -----------------------------------------------------

    print(
        "\nSaving multiclass training data..."
    )

    X_train_scaled.to_csv(
        TRAIN_OUTPUT,
        index=False
    )

    print(
        "Saving multiclass testing data..."
    )

    X_test_scaled.to_csv(
        TEST_OUTPUT,
        index=False
    )

    print(
        "Saving multiclass scaler..."
    )

    joblib.dump(
        scaler,
        SCALER_OUTPUT
    )

    # -----------------------------------------------------
    # Summary
    # -----------------------------------------------------

    print("\n" + "=" * 70)
    print("MULTICLASS DATA PREPARATION COMPLETE")
    print("=" * 70)

    print(
        f"\nTraining data:\n{TRAIN_OUTPUT}"
    )

    print(
        f"\nTesting data:\n{TEST_OUTPUT}"
    )

    print(
        f"\nScaler:\n{SCALER_OUTPUT}"
    )

    print(
        "\nTraining class distribution:"
    )

    print(
        y_train.value_counts()
    )

    print(
        "\nTesting class distribution:"
    )

    print(
        y_test.value_counts()
    )


# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":
    main()