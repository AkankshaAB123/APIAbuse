import requests
import pandas as pd


# =========================================================
# LOAD TEST DATA
# =========================================================

TEST_FILE = "ml/datasets/processed/test.csv"

print("Loading test data...")

df = pd.read_csv(TEST_FILE)

print(f"Test rows: {len(df)}")


# =========================================================
# GET FIRST ROW
# =========================================================

row = df.iloc[0]

actual_label = row["Attack"]

features = row.drop("Attack").to_dict()


# =========================================================
# SEND TO ML API
# =========================================================

print("\nSending first row to ML API...")

response = requests.post(
    "http://127.0.0.1:5000/predict",
    json={
        "features": features
    }
)


# =========================================================
# DISPLAY RESULT
# =========================================================

print("\nHTTP status:", response.status_code)

print("\nAPI response:")

print(response.json())

print("\nActual label:")

if actual_label == 1:
    print("ATTACK")
else:
    print("BENIGN")