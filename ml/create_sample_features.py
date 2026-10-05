import pandas as pd
import json
from pathlib import Path


# ============================================================
# PATH
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DATA_PATH = (
    BASE_DIR
    / "datasets"
    / "processed"
    / "test.csv"
)


# ============================================================
# LOAD DATASET
# ============================================================

print("Loading dataset...")
print(f"Dataset path: {DATA_PATH}")

if not DATA_PATH.exists():
    raise FileNotFoundError(
        f"\nDataset not found:\n{DATA_PATH}"
    )

df = pd.read_csv(
    DATA_PATH,
    low_memory=False
)

print(f"Rows: {len(df):,}")
print(f"Columns: {len(df.columns)}")


# ============================================================
# FIND LABEL COLUMN
# ============================================================

if "Attack" in df.columns:
    label_column = "Attack"
elif "Label" in df.columns:
    label_column = "Label"
else:
    raise ValueError(
        "Dataset must contain either 'Attack' or 'Label'."
    )

print(f"Label column: {label_column}")


# ============================================================
# CLEAN LABELS
# ============================================================

df[label_column] = (
    df[label_column]
    .astype(str)
    .str.strip()
)


# ============================================================
# SHOW AVAILABLE CLASSES
# ============================================================

print("\nAvailable classes:")

class_counts = df[label_column].value_counts()

for label, count in class_counts.items():
    print(f"{label}: {count:,}")


# ============================================================
# FIND A MALICIOUS CLASS
# ============================================================

malicious_classes = [
    label
    for label in class_counts.index
    if label.upper() != "BENIGN"
]


if not malicious_classes:
    raise ValueError(
        "No malicious classes found in the dataset."
    )


# Take the first available malicious class
selected_class = malicious_classes[0]

print()
print(f"Selected malicious class: {selected_class}")


# ============================================================
# SELECT ONE SAMPLE
# ============================================================

class_rows = df[
    df[label_column] == selected_class
]

row = class_rows.iloc[0]


# ============================================================
# EXTRACT FEATURES
# ============================================================

features = {}

for column in row.index:

    if column == label_column:
        continue

    value = pd.to_numeric(
        row[column],
        errors="coerce"
    )

    if pd.isna(value):
        value = 0.0

    features[column] = float(value)


# ============================================================
# VALIDATE FEATURE COUNT
# ============================================================

print(
    f"Number of features: {len(features)}"
)

if len(features) != 78:
    raise ValueError(
        f"Expected 78 features, "
        f"but found {len(features)}."
    )


# ============================================================
# SAVE JSON
# ============================================================

OUTPUT_PATH = (
    BASE_DIR
    / "sample_features.json"
)

with open(
    OUTPUT_PATH,
    "w"
) as f:

    json.dump(
        features,
        f,
        indent=4
    )


# ============================================================
# DONE
# ============================================================

print()
print("=" * 60)
print("SAMPLE CREATED")
print("=" * 60)

print(
    f"Actual dataset class : {selected_class}"
)

print(
    f"Number of features   : {len(features)}"
)

print(
    f"Output file          : {OUTPUT_PATH}"
)

print("=" * 60)