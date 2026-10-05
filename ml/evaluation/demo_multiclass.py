import pandas as pd
import json
from pathlib import Path

from ml.api.predictor import predict


# ============================================================
# PATH
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

RAW_DATA_DIR = (
    BASE_DIR
    / "datasets"
    / "CICIDS2017"
)


# ============================================================
# LOAD RAW CICIDS2017 DATA
# ============================================================

def load_raw_data():

    csv_files = list(
        RAW_DATA_DIR.glob("*.csv")
    )

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in {RAW_DATA_DIR}"
        )

    dataframes = []

    for file in csv_files:

        df = pd.read_csv(
            file,
            low_memory=False
        )

        dataframes.append(df)

    return pd.concat(
        dataframes,
        ignore_index=True
    )


# ============================================================
# MAIN
# ============================================================

def main():

    # --------------------------------------------------------
    # Load dataset
    # --------------------------------------------------------

    df = load_raw_data()


    # --------------------------------------------------------
    # Clean column names
    # --------------------------------------------------------

    df.columns = (
        df.columns
        .str.strip()
    )


    # --------------------------------------------------------
    # Check Label column
    # --------------------------------------------------------

    if "Label" not in df.columns:

        raise ValueError(
            "Dataset must contain a 'Label' column."
        )


    # --------------------------------------------------------
    # Take ONE row from the dataset
    # --------------------------------------------------------

    sample = df.iloc[0]


    # --------------------------------------------------------
    # Remove Label
    #
    # The predictor receives only the network features.
    # --------------------------------------------------------

    features = (
        sample
        .drop(labels=["Label"])
        .to_dict()
    )


    # --------------------------------------------------------
    # Convert feature values to numbers
    # --------------------------------------------------------

    cleaned_features = {}

    for feature, value in features.items():

        try:

            value = float(value)

        except (
            ValueError,
            TypeError
        ):

            value = 0.0

        cleaned_features[feature] = value


    # --------------------------------------------------------
    # Call predictor
    # --------------------------------------------------------

    result = predict(
        cleaned_features
    )


    # --------------------------------------------------------
    # If predictor returns JSON string,
    # convert it to a Python object.
    # --------------------------------------------------------

    if isinstance(result, str):

        result = json.loads(
            result
        )


    # --------------------------------------------------------
    # OUTPUT JSON ONLY
    # --------------------------------------------------------

    print(
        json.dumps(
            result,
            indent=4
        )
    )


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    main()