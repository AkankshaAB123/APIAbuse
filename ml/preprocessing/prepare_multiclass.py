import pandas as pd
import numpy as np
import joblib

from pathlib import Path
from sklearn.preprocessing import StandardScaler


# =========================================================
# PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

RAW_DATA_DIR = (
    BASE_DIR
    / "datasets"
    / "raw"
    / "CICIDS2017"
)

OUTPUT_DIR = (
    BASE_DIR
    / "datasets"
    / "processed"
)

TRAIN_OUTPUT = (
    OUTPUT_DIR
    / "multiclass_train_scaled.csv"
)

TEST_OUTPUT = (
    OUTPUT_DIR
    / "multiclass_test_scaled.csv"
)

SCALER_OUTPUT = (
    BASE_DIR
    / "models"
    / "multiclass_scaler.pkl"
)


# =========================================================
# SETTINGS
# =========================================================

TEST_SIZE = 0.20
RANDOM_STATE = 42

# Number of different file combinations to try
MAX_ATTEMPTS = 1000


# =========================================================
# LOAD ORIGINAL CICIDS2017 FILES
# =========================================================

def load_original_data():

    print("=" * 70)
    print("MULTICLASS FILE-BASED DATA PREPARATION")
    print("=" * 70)

    print("\nLooking for original CICIDS2017 CSV files...")

    csv_files = sorted(
        RAW_DATA_DIR.glob("*.csv")
    )

    if not csv_files:

        raise FileNotFoundError(
            f"\nNo CSV files found in:\n"
            f"{RAW_DATA_DIR}\n\n"
            f"Put the original CICIDS2017 CSV files "
            f"in this directory."
        )

    print(
        f"\nFound {len(csv_files)} CSV files:"
    )

    for file in csv_files:

        print(
            f"  - {file.name}"
        )

    frames = []

    for file in csv_files:

        print(
            f"\nLoading: {file.name}"
        )

        df = pd.read_csv(
            file,
            low_memory=False
        )

        # Keep track of the original CICIDS file.
        # This will be used as the grouping variable.
        df["_source_file"] = file.name

        print(
            f"Rows: {len(df):,}"
        )

        frames.append(df)

    print(
        "\nCombining datasets..."
    )

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

    print(
        "\nCleaning attack labels..."
    )

    df["Label"] = (
        df["Label"]
        .astype(str)
        .str.strip()
    )

    # Remove empty labels
    df = df[
        df["Label"].notna()
        & (df["Label"] != "")
    ]

    print(
        "\nAttack type distribution:"
    )

    print(
        df["Label"].value_counts()
    )

    return df


# =========================================================
# CLEAN FEATURES
# =========================================================

def clean_features(X):

    print(
        "\nCleaning numerical features..."
    )

    # Convert all feature columns to numeric
    for column in X.columns:

        X[column] = pd.to_numeric(
            X[column],
            errors="coerce"
        )

    # Replace infinity values with NaN
    X = X.replace(
        [np.inf, -np.inf],
        np.nan
    )

    # IMPORTANT:
    #
    # We intentionally DO NOT fill NaN values here.
    #
    # The medians will be calculated only from
    # the training set after the train/test split.
    #
    # This prevents information from the test set
    # leaking into training.

    return X


# =========================================================
# FIND FILES CONTAINING EACH CLASS
# =========================================================

def get_class_file_information(y, groups):

    class_files = {}

    for label in sorted(
        y.unique()
    ):

        files = sorted(
            groups[
                y == label
            ].unique()
        )

        class_files[label] = files

    return class_files


# =========================================================
# FIND VALID FILE-BASED SPLIT
# =========================================================

def find_group_split(X, y, groups):

    print(
        "\n" + "=" * 70
    )

    print(
        "ANALYZING FILE-LEVEL CLASS DISTRIBUTION"
    )

    print(
        "=" * 70
    )

    # -----------------------------------------------------
    # Determine which files contain each attack class
    # -----------------------------------------------------

    class_files = get_class_file_information(
        y,
        groups
    )

    # -----------------------------------------------------
    # Classes occurring in only one file
    # -----------------------------------------------------

    mandatory_train_files = set()

    print(
        "\nClass/file information:"
    )

    for label, files in class_files.items():

        print(
            f"\n{label}:"
        )

        print(
            f"  Number of source files: {len(files)}"
        )

        for file in files:

            print(
                f"    - {file}"
            )

        # If an attack occurs in only one file,
        # that file MUST remain in training.
        if len(files) == 1:

            only_file = files[0]

            mandatory_train_files.add(
                only_file
            )

            print(
                "  -> This class occurs in only one file."
            )

            print(
                "  -> Keeping that file in TRAINING."
            )

    # -----------------------------------------------------
    # Get all source files
    # -----------------------------------------------------

    all_files = sorted(
        groups.unique()
    )

    candidate_test_files = [
        file
        for file in all_files
        if file not in mandatory_train_files
    ]

    print(
        "\n" + "=" * 70
    )

    print(
        "FILE SPLIT INFORMATION"
    )

    print(
        "=" * 70
    )

    print(
        f"\nTotal source files: "
        f"{len(all_files)}"
    )

    print(
        f"Mandatory training files: "
        f"{len(mandatory_train_files)}"
    )

    print(
        f"Candidate testing files: "
        f"{len(candidate_test_files)}"
    )

    # -----------------------------------------------------
    # Target test size
    # -----------------------------------------------------

    total_rows = len(y)

    target_test_rows = (
        total_rows * TEST_SIZE
    )

    print(
        f"\nTotal rows: "
        f"{total_rows:,}"
    )

    print(
        f"Target testing rows: "
        f"{target_test_rows:,.0f}"
    )

    # -----------------------------------------------------
    # Random generator
    # -----------------------------------------------------

    rng = np.random.RandomState(
        RANDOM_STATE
    )

    best_train_mask = None
    best_test_mask = None

    best_difference = float("inf")

    # -----------------------------------------------------
    # Try many possible combinations of files
    # -----------------------------------------------------

    for attempt in range(
        MAX_ATTEMPTS
    ):

        shuffled_files = (
            candidate_test_files.copy()
        )

        rng.shuffle(
            shuffled_files
        )

        selected_test_files = []

        test_rows = 0

        # -------------------------------------------------
        # Add files until approximately 20% is reached
        # -------------------------------------------------

        for file in shuffled_files:

            file_rows = int(
                (groups == file).sum()
            )

            # Add the file if we are still below target.
            #
            # Once we pass the target, stop.
            if (
                test_rows < target_test_rows
                or len(selected_test_files) == 0
            ):

                selected_test_files.append(
                    file
                )

                test_rows += file_rows

            else:

                break

        # -------------------------------------------------
        # Create train/test file lists
        # -------------------------------------------------

        train_files = [
            file
            for file in all_files
            if file not in selected_test_files
        ]

        # -------------------------------------------------
        # Safety check:
        # mandatory files cannot be in test
        # -------------------------------------------------

        if any(
            file in selected_test_files
            for file in mandatory_train_files
        ):

            continue

        # -------------------------------------------------
        # Create masks
        # -------------------------------------------------

        train_mask = groups.isin(
            train_files
        )

        test_mask = groups.isin(
            selected_test_files
        )

        # -------------------------------------------------
        # Determine classes
        # -------------------------------------------------

        train_classes = set(
            y[
                train_mask
            ].unique()
        )

        test_classes = set(
            y[
                test_mask
            ].unique()
        )

        # -------------------------------------------------
        # Every test class must exist in training
        # -------------------------------------------------

        unseen_test_classes = (
            test_classes - train_classes
        )

        if len(unseen_test_classes) > 0:

            continue

        # -------------------------------------------------
        # Calculate test ratio
        # -------------------------------------------------

        actual_test_ratio = (
            test_mask.sum()
            / total_rows
        )

        difference = abs(
            actual_test_ratio
            - TEST_SIZE
        )

        # -------------------------------------------------
        # Keep best split
        # -------------------------------------------------

        if difference < best_difference:

            best_difference = difference

            best_train_mask = train_mask.copy()
            best_test_mask = test_mask.copy()

    # -----------------------------------------------------
    # Check whether a valid split was found
    # -----------------------------------------------------

    if best_train_mask is None:

        raise RuntimeError(
            "\nCould not find a valid file-based split."
            "\n\n"
            "The dataset may contain too few source files "
            "to create a 20% file-level test set while "
            "keeping all test classes represented in training."
        )

    # -----------------------------------------------------
    # Get final files
    # -----------------------------------------------------

    final_train_files = sorted(
        groups[
            best_train_mask
        ].unique()
    )

    final_test_files = sorted(
        groups[
            best_test_mask
        ].unique()
    )

    # -----------------------------------------------------
    # Print final split
    # -----------------------------------------------------

    print(
        "\n" + "=" * 70
    )

    print(
        "VALID FILE-BASED SPLIT FOUND"
    )

    print(
        "=" * 70
    )

    print(
        "\nTRAINING FILES:"
    )

    for file in final_train_files:

        rows = int(
            (groups == file).sum()
        )

        print(
            f"  - {file} "
            f"({rows:,} rows)"
        )

    print(
        "\nTESTING FILES:"
    )

    for file in final_test_files:

        rows = int(
            (groups == file).sum()
        )

        print(
            f"  - {file} "
            f"({rows:,} rows)"
        )

    # -----------------------------------------------------
    # Print sizes
    # -----------------------------------------------------

    train_rows = int(
        best_train_mask.sum()
    )

    test_rows = int(
        best_test_mask.sum()
    )

    print(
        f"\nTraining rows: "
        f"{train_rows:,}"
    )

    print(
        f"Testing rows:  "
        f"{test_rows:,}"
    )

    print(
        f"Actual test ratio: "
        f"{test_rows / total_rows:.2%}"
    )

    # -----------------------------------------------------
    # Print classes
    # -----------------------------------------------------

    train_classes = sorted(
        y[
            best_train_mask
        ].unique()
    )

    test_classes = sorted(
        y[
            best_test_mask
        ].unique()
    )

    print(
        f"\nTraining classes: "
        f"{len(train_classes)}"
    )

    for label in train_classes:

        print(
            f"  - {label}"
        )

    print(
        f"\nTesting classes: "
        f"{len(test_classes)}"
    )

    for label in test_classes:

        print(
            f"  - {label}"
        )

    # -----------------------------------------------------
    # Final safety check
    # -----------------------------------------------------

    missing_from_training = (
        set(test_classes)
        - set(train_classes)
    )

    if missing_from_training:

        raise RuntimeError(
            "ERROR: Test contains classes missing "
            "from training."
        )

    print(
        "\nAll testing classes are represented "
        "in the training set."
    )

    return (
        best_train_mask,
        best_test_mask
    )


# =========================================================
# MAIN
# =========================================================

def main():

    # =====================================================
    # LOAD DATA
    # =====================================================

    df = load_original_data()

    # =====================================================
    # CLEAN COLUMN NAMES
    # =====================================================

    df = clean_column_names(
        df
    )

    # =====================================================
    # CLEAN LABELS
    # =====================================================

    df = clean_labels(
        df
    )

    # =====================================================
    # GROUP IDENTIFIER
    # =====================================================

    groups = df[
        "_source_file"
    ].copy()

    # =====================================================
    # FEATURES
    # =====================================================

    X = df.drop(
        columns=[
            "Label",
            "_source_file"
        ]
    )

    # =====================================================
    # LABEL
    # =====================================================

    y = df[
        "Label"
    ].copy()

    # =====================================================
    # CLEAN FEATURES
    # =====================================================

    X = clean_features(
        X
    )

    # =====================================================
    # KEEP NUMERICAL FEATURES ONLY
    # =====================================================

    X = X.select_dtypes(
        include=[np.number]
    )

    print(
        f"\nFeature count: "
        f"{X.shape[1]}"
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

            print(
                f"  - {column}"
            )

    # =====================================================
    # REMOVE INVALID ROWS
    # =====================================================

    print(
        "\nChecking for completely invalid rows..."
    )

    # At this stage, NaN is allowed because we will
    # perform median imputation AFTER splitting.
    #
    # We only remove rows where every feature is missing.

    valid_rows = (
        X.notna().any(axis=1)
    )

    removed_rows = (
        (~valid_rows).sum()
    )

    if removed_rows > 0:

        print(
            f"Removing {removed_rows:,} "
            f"completely invalid rows."
        )

    X = X.loc[
        valid_rows
    ].copy()

    y = y.loc[
        valid_rows
    ].copy()

    groups = groups.loc[
        valid_rows
    ].copy()

    # Reset indexes
    X.reset_index(
        drop=True,
        inplace=True
    )

    y.reset_index(
        drop=True,
        inplace=True
    )

    groups.reset_index(
        drop=True,
        inplace=True
    )

    # =====================================================
    # FILE-BASED SPLIT
    # =====================================================

    train_mask, test_mask = find_group_split(
        X,
        y,
        groups
    )

    # =====================================================
    # CREATE TRAIN / TEST SETS
    # =====================================================

    X_train = X.loc[
        train_mask
    ].copy()

    X_test = X.loc[
        test_mask
    ].copy()

    y_train = y.loc[
        train_mask
    ].copy()

    y_test = y.loc[
        test_mask
    ].copy()

    # =====================================================
    # PRINT INITIAL DISTRIBUTIONS
    # =====================================================

    print(
        "\n" + "=" * 70
    )

    print(
        "TRAINING CLASS DISTRIBUTION"
    )

    print(
        "=" * 70
    )

    print(
        y_train.value_counts()
    )

    print(
        "\n" + "=" * 70
    )

    print(
        "TESTING CLASS DISTRIBUTION"
    )

    print(
        "=" * 70
    )

    print(
        y_test.value_counts()
    )

    # =====================================================
    # MEDIAN IMPUTATION
    # =====================================================

    print(
        "\n" + "=" * 70
    )

    print(
        "MISSING VALUE IMPUTATION"
    )

    print(
        "=" * 70
    )

    print(
        "\nCalculating feature medians "
        "from TRAINING data only..."
    )

    train_medians = (
        X_train.median()
    )

    # Fill training values
    X_train = X_train.fillna(
        train_medians
    )

    # Fill testing values using
    # training medians
    X_test = X_test.fillna(
        train_medians
    )

    remaining_train_nan = (
        X_train.isna().sum().sum()
    )

    remaining_test_nan = (
        X_test.isna().sum().sum()
    )

    print(
        f"\nRemaining training NaN values: "
        f"{remaining_train_nan}"
    )

    print(
        f"Remaining testing NaN values: "
        f"{remaining_test_nan}"
    )

    # =====================================================
    # STANDARD SCALER
    # =====================================================

    print(
        "\n" + "=" * 70
    )

    print(
        "FEATURE SCALING"
    )

    print(
        "=" * 70
    )

    print(
        "\nFitting StandardScaler "
        "on training data..."
    )

    scaler = StandardScaler()

    X_train_scaled = (
        scaler.fit_transform(
            X_train
        )
    )

    print(
        "Transforming testing data..."
    )

    X_test_scaled = (
        scaler.transform(
            X_test
        )
    )

    # =====================================================
    # CONVERT BACK TO DATAFRAME
    # =====================================================

    X_train_scaled = pd.DataFrame(
        X_train_scaled,
        columns=X_train.columns
    )

    X_test_scaled = pd.DataFrame(
        X_test_scaled,
        columns=X_test.columns
    )

    # =====================================================
    # ADD LABEL
    # =====================================================

    X_train_scaled["Label"] = (
        y_train.to_numpy()
    )

    X_test_scaled["Label"] = (
        y_test.to_numpy()
    )

    # =====================================================
    # CREATE OUTPUT DIRECTORIES
    # =====================================================

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    SCALER_OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # =====================================================
    # SAVE TRAINING DATA
    # =====================================================

    print(
        "\n" + "=" * 70
    )

    print(
        "SAVING DATA"
    )

    print(
        "=" * 70
    )

    print(
        "\nSaving multiclass training data..."
    )

    X_train_scaled.to_csv(
        TRAIN_OUTPUT,
        index=False
    )

    print(
        f"Saved to:\n{TRAIN_OUTPUT}"
    )

    # =====================================================
    # SAVE TESTING DATA
    # =====================================================

    print(
        "\nSaving multiclass testing data..."
    )

    X_test_scaled.to_csv(
        TEST_OUTPUT,
        index=False
    )

    print(
        f"Saved to:\n{TEST_OUTPUT}"
    )

    # =====================================================
    # SAVE SCALER
    # =====================================================

    print(
        "\nSaving StandardScaler..."
    )

    joblib.dump(
        scaler,
        SCALER_OUTPUT
    )

    print(
        f"Saved to:\n{SCALER_OUTPUT}"
    )

    # =====================================================
    # FINAL VALIDATION
    # =====================================================

    print(
        "\n" + "=" * 70
    )

    print(
        "FINAL VALIDATION"
    )

    print(
        "=" * 70
    )

    print(
        f"\nTraining rows: "
        f"{len(X_train_scaled):,}"
    )

    print(
        f"Testing rows:  "
        f"{len(X_test_scaled):,}"
    )

    print(
        f"Training features: "
        f"{len(X_train_scaled.columns) - 1}"
    )

    print(
        f"Testing features: "
        f"{len(X_test_scaled.columns) - 1}"
    )

    # Check that there are no NaN values
    if X_train_scaled.isna().any().any():

        raise RuntimeError(
            "Training data still contains NaN values."
        )

    if X_test_scaled.isna().any().any():

        raise RuntimeError(
            "Testing data still contains NaN values."
        )

    # Check that train/test feature columns match
    train_features = list(
        X_train_scaled.columns[:-1]
    )

    test_features = list(
        X_test_scaled.columns[:-1]
    )

    if train_features != test_features:

        raise RuntimeError(
            "Training and testing feature columns do not match."
        )

    # Check classes
    train_classes = set(
        y_train.unique()
    )

    test_classes = set(
        y_test.unique()
    )

    missing_classes = (
        test_classes - train_classes
    )

    if missing_classes:

        raise RuntimeError(
            "The following testing classes are missing "
            f"from training: {missing_classes}"
        )

    print(
        "\nValidation successful."
    )

    # =====================================================
    # COMPLETE
    # =====================================================

    print(
        "\n" + "=" * 70
    )

    print(
        "MULTICLASS FILE-BASED DATA PREPARATION COMPLETE"
    )

    print(
        "=" * 70
    )

    print(
        "\nOutput files:"
    )

    print(
        f"\nTraining:"
        f"\n{TRAIN_OUTPUT}"
    )

    print(
        f"\nTesting:"
        f"\n{TEST_OUTPUT}"
    )

    print(
        f"\nScaler:"
        f"\n{SCALER_OUTPUT}"
    )

    print(
        "\nThe dataset is ready for XGBoost training."
    )


# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":

    main()