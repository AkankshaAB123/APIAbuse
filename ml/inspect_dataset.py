import pandas as pd
from pathlib import Path


DATASET_DIR = Path(__file__).resolve().parent / "datasets" / "CICIDS2017"


def inspect_file(file_path):
    print("\n" + "=" * 70)
    print(f"FILE: {file_path.name}")
    print("=" * 70)

    label_counts = {}
    total_rows = 0

    try:
        # Read the CSV in chunks
        for chunk in pd.read_csv(
            file_path,
            chunksize=50000,
            low_memory=False
        ):

            # Find Label column regardless of whitespace
            label_column = None

            for column in chunk.columns:
                if column.strip().lower() == "label":
                    label_column = column
                    break

            if label_column is None:
                print("ERROR: Label column not found.")
                return

            labels = chunk[label_column].astype(str).str.strip()

            counts = labels.value_counts()

            for label, count in counts.items():
                label_counts[label] = label_counts.get(label, 0) + count

            total_rows += len(chunk)

        print(f"\nTotal rows: {total_rows:,}")

        print("\nLabel distribution:")

        for label, count in sorted(
            label_counts.items(),
            key=lambda x: x[1],
            reverse=True
        ):
            percentage = (count / total_rows) * 100
            print(f"  {label}: {count:,} ({percentage:.2f}%)")

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