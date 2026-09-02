import pandas as pd
from pathlib import Path

from ml.api.predictor import predict


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

RAW_DATA_DIR = (
    BASE_DIR
    / "datasets"
    / "CICIDS2017"
)


# ============================================================
# SETTINGS
# ============================================================

# Number of examples to test from each attack class
SAMPLES_PER_CLASS = 1


# ============================================================
# LOAD RAW CICIDS2017 DATA
# ============================================================

def load_raw_data():

    print("=" * 70)
    print("LOADING RAW CICIDS2017 DATA")
    print("=" * 70)

    csv_files = list(
        RAW_DATA_DIR.glob("*.csv")
    )

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in {RAW_DATA_DIR}"
        )

    print(f"\nFound {len(csv_files)} CSV files.")

    dataframes = []

    for file in csv_files:

        print(
            f"Loading: {file.name}"
        )

        df = pd.read_csv(
            file,
            low_memory=False
        )

        print(
            f"Rows: {len(df):,}"
        )

        dataframes.append(df)

    print("\nCombining datasets...")

    combined = pd.concat(
        dataframes,
        ignore_index=True
    )

    print(
        f"Total rows: {len(combined):,}"
    )

    return combined


# ============================================================
# CLEAN COLUMN NAMES
# ============================================================

def clean_columns(df):

    df.columns = (
        df.columns
        .str.strip()
    )

    return df


# ============================================================
# CLEAN LABELS
# ============================================================

def clean_labels(df):

    if "Label" not in df.columns:

        raise ValueError(
            "Dataset does not contain a 'Label' column."
        )

    df["Label"] = (
        df["Label"]
        .astype(str)
        .str.strip()
    )

    return df


# ============================================================
# CLEAN NUMERICAL FEATURES
# ============================================================

def clean_features(df):

    feature_columns = [
        column
        for column in df.columns
        if column != "Label"
    ]

    for column in feature_columns:

        df[column] = pd.to_numeric(
            df[column],
            errors="coerce"
        )

    # Replace infinity
    df[feature_columns] = (
        df[feature_columns]
        .replace(
            [float("inf"), float("-inf")],
            0
        )
    )

    # Replace NaN
    df[feature_columns] = (
        df[feature_columns]
        .fillna(0)
    )

    return df


# ============================================================
# GET FEATURE DICTIONARY
# ============================================================

def row_to_features(row):

    features = {}

    for column in row.index:

        if column == "Label":
            continue

        features[column] = float(
            row[column]
        )

    return features


# ============================================================
# PRINT PREDICTION
# ============================================================

def print_prediction(
    actual_label,
    result,
    sample_number
):

    print("\n")
    print("=" * 70)
    print(
        f"SAMPLE {sample_number}"
    )
    print("=" * 70)

    print(
        f"\nActual attack     : {actual_label}"
    )

    print(
        f"Predicted attack  : {result['prediction']}"
    )

    print(
        f"Confidence         : "
        f"{result['confidence'] * 100:.2f}%"
    )

    print(
        f"Model              : "
        f"{result['model']}"
    )

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    correct = (
        actual_label
        == result["prediction"]
    )

    print(
        f"\nCorrect            : "
        f"{correct}"
    )

    # --------------------------------------------------------
    # Attack explanation
    # --------------------------------------------------------

    if "attack_explanation" in result:

        explanation = (
            result["attack_explanation"]
        )

        print("\n")
        print(
            "ATTACK EXPLANATION"
        )
        print("-" * 70)

        print(
            explanation.get(
                "summary",
                "No explanation available."
            )
        )

        characteristics = (
            explanation.get(
                "characteristics",
                []
            )
        )

        if characteristics:

            print("\nCharacteristics:")

            for characteristic in characteristics:

                print(
                    f"  • {characteristic}"
                )

    # --------------------------------------------------------
    # Feature reasons
    # --------------------------------------------------------

    reasons = result.get(
        "reasons",
        []
    )

    if reasons:

        print("\n")
        print(
            "IMPORTANT FEATURES"
        )
        print("-" * 70)

        for reason in reasons:

            print(
                f"\nFeature      : "
                f"{reason.get('feature')}"
            )

            print(
                f"Value        : "
                f"{reason.get('value'):.4f}"
            )

            print(
                f"Importance   : "
                f"{reason.get('importance'):.4f}"
            )

            print(
                f"Explanation  : "
                f"{reason.get('explanation')}"
            )


# ============================================================
# MAIN
# ============================================================

def main():

    print("\n")
    print("=" * 70)
    print("CICIDS2017 MULTICLASS ATTACK DEMO")
    print("=" * 70)

    # --------------------------------------------------------
    # Load RAW data
    # --------------------------------------------------------

    df = load_raw_data()

    # --------------------------------------------------------
    # Clean
    # --------------------------------------------------------

    print("\nCleaning dataset...")

    df = clean_columns(df)

    df = clean_labels(df)

    df = clean_features(df)

    # --------------------------------------------------------
    # Show available classes
    # --------------------------------------------------------

    classes = sorted(
        df["Label"]
        .unique()
        .tolist()
    )

    print("\n")
    print("=" * 70)
    print("AVAILABLE CLASSES")
    print("=" * 70)

    for attack_class in classes:

        count = (
            df["Label"]
            == attack_class
        ).sum()

        print(
            f"{attack_class:<35} "
            f"{count:,} rows"
        )

    # --------------------------------------------------------
    # Select one real sample from each class
    # --------------------------------------------------------

    print("\n")
    print("=" * 70)
    print("TESTING ONE REAL SAMPLE FROM EACH CLASS")
    print("=" * 70)

    sample_number = 0

    results = []

    for attack_class in classes:

        class_rows = df[
            df["Label"]
            == attack_class
        ]

        if len(class_rows) == 0:
            continue

        samples = class_rows.head(
            SAMPLES_PER_CLASS
        )

        for _, row in samples.iterrows():

            sample_number += 1

            actual_label = (
                row["Label"]
            )

            # ------------------------------------------------
            # IMPORTANT:
            # These are RAW feature values.
            #
            # We do NOT use multiclass_test_scaled.csv.
            #
            # predictor.py will perform scaling.
            # ------------------------------------------------

            features = row_to_features(
                row
            )

            print("\n")
            print("=" * 70)

            print(
                f"Testing class: "
                f"{actual_label}"
            )

            print(
                f"Number of features: "
                f"{len(features)}"
            )

            print(
                "Passing RAW features "
                "to predictor..."
            )

            # ------------------------------------------------
            # Prediction
            # ------------------------------------------------

            try:

                result = predict(
                    features
                )

                print_prediction(
                    actual_label,
                    result,
                    sample_number
                )

                results.append(
                    {
                        "actual": actual_label,
                        "predicted": result[
                            "prediction"
                        ],
                        "confidence": result[
                            "confidence"
                        ],
                        "correct": (
                            actual_label
                            == result["prediction"]
                        )
                    }
                )

            except Exception as e:

                print(
                    "\nPrediction failed:"
                )

                print(e)

    # ========================================================
    # SUMMARY
    # ========================================================

    print("\n")
    print("=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)

    if results:

        results_df = pd.DataFrame(
            results
        )

        print()

        print(
            results_df.to_string(
                index=False
            )
        )

        accuracy = (
            results_df["correct"]
            .mean()
        )

        print("\n")
        print(
            f"Samples tested : "
            f"{len(results)}"
        )

        print(
            f"Correct        : "
            f"{results_df['correct'].sum()}"
        )

        print(
            f"Accuracy       : "
            f"{accuracy * 100:.2f}%"
        )

    print("\n")
    print("=" * 70)
    print("DEMO COMPLETE")
    print("=" * 70)


if __name__ == "__main__":

    main()