import pandas as pd
from pathlib import Path


DATASET_DIR = Path("ml/datasets/CICIDS2017")


def inspect_file(file_path):
    print("\n" + "=" * 70)
    print(f"FILE: {file_path.name}")
    print("=" * 70)

    try:
        df = pd.read_csv(file_path, low_memory=False)

        print(f"\nRows: {df.shape[0]}")
        print(f"Columns: {df.shape[1]}")

        print("\nColumn names:")
        for column in df.columns:
            print(f"  - {column}")

        # Find Label column
        label_column = None

        for column in df.columns:
            if column.strip().lower() == "label":
                label_column = column
                break

        if label_column:
            print("\nLabel distribution:")
            print(df[label_column].value_counts())

            print("\nLabel distribution (%):")
            print(
                df[label_column]
                .value_counts(normalize=True)
                .mul(100)
                .round(2)
            )
        else:
            print("\nWARNING: No Label column found.")

        # Missing values
        print("\nMissing values:")

        missing = df.isnull().sum()
        missing = missing[missing > 0]

        if len(missing) == 0:
            print("  No missing values found.")
        else:
            print(missing)

        # Infinite values
        print("\nInfinite values:")

        numeric_df = df.select_dtypes(include="number")

        infinite_count = numeric_df.isin(
            [float("inf"), float("-inf")]
        ).sum().sum()

        print(f"  Total infinite values: {infinite_count}")

    except Exception as e:
        print("\nERROR:")
        print(e)


def main():

    if not DATASET_DIR.exists():
        print(f"Dataset folder not found: {DATASET_DIR}")
        return

    csv_files = list(DATASET_DIR.glob("*.csv"))

    if not csv_files:
        print("No CSV files found.")
        return

    print(f"Found {len(csv_files)} CSV files.")

    for file_path in csv_files:
        inspect_file(file_path)


if __name__ == "__main__":
    main()