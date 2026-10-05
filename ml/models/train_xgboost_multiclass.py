import pandas as pd
import joblib

from pathlib import Path
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder


# =========================================================
# PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

TRAIN_FILE = (
    BASE_DIR
    / "datasets"
    / "processed"
    / "multiclass_train_scaled.csv"
)

MODEL_DIR = BASE_DIR / "models"

MODEL_FILE = (
    MODEL_DIR
    / "xgboost_multiclass.pkl"
)

ENCODER_FILE = (
    MODEL_DIR
    / "multiclass_label_encoder.pkl"
)


# =========================================================
# SETTINGS
# =========================================================

RANDOM_STATE = 42


# =========================================================
# START
# =========================================================

print("=" * 70)
print("XGBOOST MULTICLASS TRAINING")
print("=" * 70)


# =========================================================
# LOAD TRAINING DATA
# =========================================================

print("\nLoading training data...")

df = pd.read_csv(
    TRAIN_FILE,
    low_memory=False
)

print(
    f"Training rows: {len(df):,}"
)

print(
    f"Training columns: {len(df.columns)}"
)


# =========================================================
# CHECK LABEL
# =========================================================

if "Label" not in df.columns:
    raise ValueError(
        "Label column not found in multiclass training dataset."
    )


# =========================================================
# SEPARATE FEATURES AND LABEL
# =========================================================

print("\nSeparating features and labels...")

X = df.drop(
    columns=["Label"]
)

y = df["Label"]


print(
    f"Number of features: {X.shape[1]}"
)

if X.shape[1] != 78:
    raise ValueError(
        f"Expected 78 features, found {X.shape[1]}"
    )


# =========================================================
# DISPLAY CLASS DISTRIBUTION
# =========================================================

print("\nAttack class distribution:")

print(
    y.value_counts()
)


# =========================================================
# ENCODE LABELS
# =========================================================

print("\nEncoding attack labels...")

label_encoder = LabelEncoder()

y_encoded = label_encoder.fit_transform(
    y
)


# =========================================================
# DISPLAY CLASS MAPPING
# =========================================================

print("\nClass mapping:")

for index, class_name in enumerate(
    label_encoder.classes_
):
    print(
        f"{index}: {class_name}"
    )


number_of_classes = len(
    label_encoder.classes_
)

print(
    f"\nTotal classes: {number_of_classes}"
)


# =========================================================
# CREATE XGBOOST MODEL
# =========================================================

print("\nCreating XGBoost multiclass model...")

model = XGBClassifier(
    objective="multi:softprob",

    num_class=number_of_classes,

    n_estimators=300,

    max_depth=8,

    learning_rate=0.1,

    subsample=0.8,

    colsample_bytree=0.8,

    random_state=RANDOM_STATE,

    n_jobs=-1,

    eval_metric="mlogloss"
)


# =========================================================
# TRAIN
# =========================================================

print("\nTraining XGBoost...")

print(
    "This may take a while because the dataset "
    "contains more than 2 million rows."
)

model.fit(
    X,
    y_encoded
)


print("\nTraining complete!")


# =========================================================
# CREATE MODEL DIRECTORY
# =========================================================

MODEL_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# =========================================================
# SAVE MODEL
# =========================================================

print("\nSaving multiclass model...")

joblib.dump(
    model,
    MODEL_FILE
)

print(
    f"Model saved to:\n{MODEL_FILE}"
)


# =========================================================
# SAVE LABEL ENCODER
# =========================================================

print("\nSaving label encoder...")

joblib.dump(
    label_encoder,
    ENCODER_FILE
)

print(
    f"Label encoder saved to:\n{ENCODER_FILE}"
)


# =========================================================
# FINAL SUMMARY
# =========================================================

print("\n" + "=" * 70)
print("XGBOOST MULTICLASS TRAINING COMPLETE")
print("=" * 70)

print(
    f"\nModel:"
)

print(
    MODEL_FILE
)

print(
    "\nLabel encoder:"
)

print(
    ENCODER_FILE
)

print(
    "\nClasses:"
)

for index, class_name in enumerate(
    label_encoder.classes_
):
    print(
        f"  {index} -> {class_name}"
    )

print(
    "\n" + "=" * 70
)