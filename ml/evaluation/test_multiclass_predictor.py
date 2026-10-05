import pandas as pd
import numpy as np

from ml.api.predictor import predict


# =========================================================
# PATH
# =========================================================

TEST_FILE = (
    "ml/datasets/processed/multiclass_test_scaled.csv"
)


# =========================================================
# MAIN
# =========================================================

def main():

    print("=" * 70)
    print("MULTICLASS ATTACK TEST")
    print("=" * 70)

    # -----------------------------------------------------
    # Load dataset
    # -----------------------------------------------------

    print("\nLoading multiclass test data...")

    df = pd.read_csv(
        TEST_FILE,
        low_memory=False
    )

    print(
        f"Test rows: {len(df):,}"
    )

    print(
        f"Test columns: {len(df.columns)}"
    )

    # -----------------------------------------------------
    # Identify label column
    # -----------------------------------------------------

    if "Label" in df.columns:
        label_column = "Label"

    elif "Attack" in df.columns:
        label_column = "Attack"

    else:
        raise ValueError(
            "Could not find Label or Attack column."
        )

    print(
        f"Label column: {label_column}"
    )

    # -----------------------------------------------------
    # Feature columns
    # -----------------------------------------------------

    feature_columns = [
        column
        for column in df.columns
        if column != label_column
    ]

    print(
        f"Feature count: {len(feature_columns)}"
    )

    # -----------------------------------------------------
    # Find classes
    # -----------------------------------------------------

    classes = sorted(
        df[label_column]
        .dropna()
        .unique()
    )

    print(
        f"\nFound {len(classes)} classes:"
    )

    for attack_class in classes:
        count = (
            df[label_column] == attack_class
        ).sum()

        print(
            f"  - {attack_class}: "
            f"{count:,} samples"
        )

    # =====================================================
    # TEST EACH CLASS
    # =====================================================

    print("\n")
    print("=" * 70)
    print("TESTING ONE DIFFERENT SAMPLE FROM EACH CLASS")
    print("=" * 70)

    results = []

    for attack_class in classes:

        print("\n")
        print("-" * 70)
        print(
            f"Actual class: {attack_class}"
        )
        print("-" * 70)

        # -------------------------------------------------
        # Get ALL rows for this class
        # -------------------------------------------------

        class_rows = df[
            df[label_column] == attack_class
        ]

        if len(class_rows) == 0:

            print(
                "No samples found. Skipping."
            )

            continue

        # -------------------------------------------------
        # Pick a deterministic sample
        #
        # We use the middle of the class rather than
        # always taking the first row.
        # -------------------------------------------------

        sample_index = len(class_rows) // 2

        sample = class_rows.iloc[
            sample_index
        ]

        # -------------------------------------------------
        # Extract features ONLY
        # -------------------------------------------------

        features = (
            sample[
                feature_columns
            ]
            .astype(float)
            .to_dict()
        )

        print(
            f"Number of features: "
            f"{len(features)}"
        )

        # -------------------------------------------------
        # Show a few actual values
        #
        # This lets us verify that different classes
        # really are sending different data.
        # -------------------------------------------------

        print("\nSample feature values:")

        for feature_name in feature_columns[:5]:

            print(
                f"  {feature_name}: "
                f"{features[feature_name]:.6f}"
            )

        # -------------------------------------------------
        # Prediction
        # -------------------------------------------------

        print(
            "\nCalling ML predictor..."
        )

        try:

            result = predict(
                features
            )

            prediction = result[
                "prediction"
            ]

            confidence = float(
                result["confidence"]
            )

            correct = (
                prediction == attack_class
            )

            # -------------------------------------------------
            # Print result
            # -------------------------------------------------

            print("\nPrediction:")
            print(
                f"  Actual     : "
                f"{attack_class}"
            )

            print(
                f"  Predicted  : "
                f"{prediction}"
            )

            print(
                f"  Confidence : "
                f"{confidence * 100:.2f}%"
            )

            print(
                f"  Correct    : "
                f"{correct}"
            )

            # -------------------------------------------------
            # Attack explanation
            # -------------------------------------------------

            explanation = result.get(
                "attack_explanation"
            )

            if prediction != "BENIGN" and explanation:

                print(
                    "\nAttack explanation:"
                )

                print(
                    f"  {explanation.get('summary', '')}"
                )

                for characteristic in (
                    explanation.get(
                        "characteristics",
                        []
                    )
                ):

                    print(
                        f"  - {characteristic}"
                    )

            # -------------------------------------------------
            # Important features
            # -------------------------------------------------

            reasons = result.get(
                "reasons",
                []
            )

            if reasons:

                print(
                    "\nImportant features:"
                )

                for reason in reasons:

                    print(
                        f"  {reason['feature']}"
                    )

                    print(
                        f"    Value: "
                        f"{reason['value']:.4f}"
                    )

                    print(
                        f"    Importance: "
                        f"{reason['importance']:.4f}"
                    )

            # -------------------------------------------------
            # Save result
            # -------------------------------------------------

            results.append({
                "actual": attack_class,
                "predicted": prediction,
                "confidence": confidence,
                "correct": correct
            })

        except Exception as e:

            print(
                f"\nPrediction failed: {e}"
            )

            results.append({
                "actual": attack_class,
                "predicted": "ERROR",
                "confidence": 0.0,
                "correct": False
            })

    # =====================================================
    # FINAL RESULTS
    # =====================================================

    print("\n")
    print("=" * 70)
    print("FINAL RESULTS")
    print("=" * 70)

    results_df = pd.DataFrame(
        results
    )

    print(
        results_df.to_string(
            index=False
        )
    )

    # -----------------------------------------------------
    # Accuracy
    # -----------------------------------------------------

    if len(results_df) > 0:

        accuracy = (
            results_df["correct"]
            .mean()
        )

        correct_count = int(
            results_df["correct"].sum()
        )

        total_count = len(
            results_df
        )

        print("\n")
        print(
            f"Sample accuracy: "
            f"{accuracy * 100:.2f}%"
        )

        print(
            f"Correct: "
            f"{correct_count}/"
            f"{total_count}"
        )

    print("\n")
    print("=" * 70)
    print(
        "MULTICLASS ATTACK TEST COMPLETE"
    )
    print("=" * 70)


# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":
    main()