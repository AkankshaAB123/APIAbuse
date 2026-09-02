import pandas as pd
import joblib
import json
from pathlib import Path


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent


# ============================================================
# BINARY MODEL
# ============================================================

BINARY_MODEL_PATH = (
    BASE_DIR
    / "models"
    / "xgboost.pkl"
)

BINARY_SCALER_PATH = (
    BASE_DIR
    / "models"
    / "scaler.pkl"
)


# ============================================================
# MULTICLASS MODEL
# ============================================================

MULTICLASS_MODEL_PATH = (
    BASE_DIR
    / "models"
    / "xgboost_multiclass.pkl"
)

MULTICLASS_SCALER_PATH = (
    BASE_DIR
    / "models"
    / "multiclass_scaler.pkl"
)

LABEL_ENCODER_PATH = (
    BASE_DIR
    / "models"
    / "multiclass_label_encoder.pkl"
)


# ============================================================
# LOAD MODELS
# ============================================================

print("Loading binary XGBoost model...")

binary_model = joblib.load(
    BINARY_MODEL_PATH
)

print("Binary XGBoost model loaded successfully.")


print("Loading binary scaler...")

binary_scaler = joblib.load(
    BINARY_SCALER_PATH
)

print("Binary scaler loaded successfully.")


print("Loading multiclass XGBoost model...")

multiclass_model = joblib.load(
    MULTICLASS_MODEL_PATH
)

print("Multiclass XGBoost model loaded successfully.")


print("Loading multiclass scaler...")

multiclass_scaler = joblib.load(
    MULTICLASS_SCALER_PATH
)

print("Multiclass scaler loaded successfully.")


print("Loading multiclass label encoder...")

label_encoder = joblib.load(
    LABEL_ENCODER_PATH
)

print("Multiclass label encoder loaded successfully.")


# ============================================================
# ATTACK EXPLANATIONS
# ============================================================

ATTACK_EXPLANATIONS = {

    "BENIGN": {
        "summary": (
            "The traffic was classified as benign because its "
            "network-flow characteristics were more consistent "
            "with normal traffic than with the attack categories "
            "learned during training."
        ),
        "characteristics": [
            "No strong learned pattern associated with an attack class",
            "Network-flow characteristics consistent with normal traffic",
            "Traffic behavior falls within patterns learned as benign"
        ]
    },


    "DDoS": {
        "summary": (
            "The traffic was classified as DDoS because its "
            "network-flow behavior matched patterns learned "
            "from distributed denial-of-service traffic."
        ),
        "characteristics": [
            "High traffic or packet volume",
            "Abnormal packet-rate behavior",
            "Large numbers of packets within network flows",
            "Flow characteristics associated with denial-of-service activity"
        ]
    },


    "DoS Hulk": {
        "summary": (
            "The traffic was classified as DoS Hulk because its "
            "network-flow behavior matched patterns associated "
            "with high-volume HTTP denial-of-service traffic."
        ),
        "characteristics": [
            "High traffic or packet rates",
            "Large numbers of network flows",
            "HTTP-oriented traffic behavior",
            "Abnormally high request activity"
        ]
    },


    "DoS GoldenEye": {
        "summary": (
            "The traffic was classified as DoS GoldenEye because "
            "its network-flow behavior matched patterns associated "
            "with repeated HTTP requests intended to consume server resources."
        ),
        "characteristics": [
            "Repeated HTTP requests",
            "High request frequency",
            "Unusual flow rates",
            "Traffic patterns associated with resource exhaustion"
        ]
    },


    "DoS slowloris": {
        "summary": (
            "The traffic was classified as DoS slowloris because "
            "its flow behavior matched patterns associated with "
            "long-lived connections and slow HTTP communication."
        ),
        "characteristics": [
            "Long connection durations",
            "Slow packet transmission",
            "Unusual flow timing",
            "Persistent connections"
        ]
    },


    "DoS Slowloris": {
        "summary": (
            "The traffic was classified as DoS Slowloris because "
            "its flow behavior matched patterns associated with "
            "long-lived connections and slow HTTP communication."
        ),
        "characteristics": [
            "Long-lived connections",
            "Slow transmission behavior",
            "Unusual inter-arrival times",
            "Low-rate but persistent traffic"
        ]
    },


    "DoS Slowhttptest": {
        "summary": (
            "The traffic was classified as DoS Slowhttptest because "
            "its network-flow behavior matched patterns associated "
            "with slow HTTP communication used to consume server resources."
        ),
        "characteristics": [
            "Slow HTTP communication",
            "Long-lived connections",
            "Unusual flow timing",
            "Low-rate persistent traffic"
        ]
    },


    "PortScan": {
        "summary": (
            "The traffic was classified as PortScan because its "
            "network-flow behavior matched patterns associated "
            "with probing multiple network ports and services."
        ),
        "characteristics": [
            "Repeated connections to destination ports",
            "Multiple probing flows",
            "Short or unusual network flows",
            "Unusual destination-port behavior"
        ]
    },


    "FTP-Patator": {
        "summary": (
            "The traffic was classified as FTP-Patator because "
            "its network-flow behavior matched patterns associated "
            "with repeated FTP authentication attempts."
        ),
        "characteristics": [
            "Repeated authentication attempts",
            "FTP-related traffic",
            "Repeated network connections",
            "Abnormal connection patterns"
        ]
    },


    "SSH-Patator": {
        "summary": (
            "The traffic was classified as SSH-Patator because "
            "its network-flow behavior matched patterns associated "
            "with repeated SSH authentication attempts."
        ),
        "characteristics": [
            "Repeated SSH connections",
            "Repeated authentication attempts",
            "Unusual connection frequency",
            "Abnormal SSH traffic patterns"
        ]
    },


    "Bot": {
        "summary": (
            "The traffic was classified as Bot because its "
            "network-flow behavior matched patterns associated "
            "with automated or compromised-system communication."
        ),
        "characteristics": [
            "Automated communication patterns",
            "Unusual network-flow behavior",
            "Repeated communication patterns",
            "Traffic characteristics associated with bot activity"
        ]
    },


    "Infiltration": {
        "summary": (
            "The traffic was classified as Infiltration because "
            "its network-flow behavior matched patterns associated "
            "with unauthorized access or suspicious internal activity."
        ),
        "characteristics": [
            "Unusual communication patterns",
            "Suspicious network flows",
            "Abnormal connection behavior",
            "Patterns associated with unauthorized network activity"
        ]
    },


    "Heartbleed": {
        "summary": (
            "The traffic was classified as Heartbleed because its "
            "network-flow behavior matched patterns associated with "
            "Heartbleed vulnerability exploitation."
        ),
        "characteristics": [
            "TLS/SSL-related traffic",
            "Unusual request and response behavior",
            "Abnormal flow characteristics",
            "Traffic associated with vulnerability exploitation"
        ]
    },


    "Web Attack � Brute Force": {
        "summary": (
            "The traffic was classified as Web Attack � Brute Force "
            "because its network-flow behavior matched patterns associated "
            "with repeated web authentication attempts."
        ),
        "characteristics": [
            "Repeated web authentication attempts",
            "High frequency of similar requests",
            "Repeated connections to web services",
            "Abnormal HTTP request patterns"
        ]
    },


    "Web Attack � XSS": {
        "summary": (
            "The traffic was classified as Web Attack � XSS because "
            "its network-flow behavior matched patterns associated "
            "with cross-site scripting activity."
        ),
        "characteristics": [
            "Suspicious web requests",
            "Unusual HTTP request patterns",
            "Potentially malicious request content",
            "Traffic patterns associated with web exploitation"
        ]
    },


    "Web Attack � Sql Injection": {
        "summary": (
            "The traffic was classified as Web Attack � Sql Injection "
            "because its network-flow behavior matched patterns associated "
            "with SQL injection activity."
        ),
        "characteristics": [
            "Suspicious web requests",
            "Abnormal HTTP traffic patterns",
            "Repeated or unusual application requests",
            "Traffic associated with web exploitation"
        ]
    }
}


# ============================================================
# VALIDATE FEATURES
# ============================================================

def validate_features(features):

    if not isinstance(features, dict):

        raise ValueError(
            "features must be a dictionary"
        )

    if not features:

        raise ValueError(
            "features cannot be empty"
        )


# ============================================================
# PREPARE FEATURES
# ============================================================

def prepare_features(features, scaler):

    X = pd.DataFrame([features])

    if hasattr(
        scaler,
        "feature_names_in_"
    ):

        expected_features = list(
            scaler.feature_names_in_
        )

        missing_features = [
            feature
            for feature in expected_features
            if feature not in X.columns
        ]

        if missing_features:

            raise ValueError(
                "Missing required features: "
                + str(missing_features)
            )

        # Keep exactly the same feature order
        # used when training the model.

        X = X[
            expected_features
        ]

    return X


# ============================================================
# GET ATTACK EXPLANATION
# ============================================================

def get_attack_explanation(
    predicted_label
):

    if predicted_label in ATTACK_EXPLANATIONS:

        return ATTACK_EXPLANATIONS[
            predicted_label
        ]

    return {

        "summary": (
            f"The traffic was classified as "
            f"{predicted_label} because its network-flow "
            f"characteristics matched patterns learned "
            f"by the trained model for this class."
        ),

        "characteristics": [
            "The observed flow resembles this class",
            "The classification is based on learned network-flow patterns",
            "Important model features are provided separately"
        ]
    }


# ============================================================
# GET FEATURE REASONS
# ============================================================

def get_feature_reasons(
    X_scaled,
    top_n=5
):

    try:

        # Get feature names from scaler

        feature_names = list(
            multiclass_scaler.feature_names_in_
        )

    except AttributeError:

        feature_names = [
            f"feature_{i}"
            for i in range(
                X_scaled.shape[1]
            )
        ]


    try:

        # XGBoost global feature importance

        importance = (
            multiclass_model.feature_importances_
        )

        feature_pairs = list(
            zip(
                feature_names,
                importance
            )
        )


        # Highest importance first

        feature_pairs.sort(
            key=lambda x: x[1],
            reverse=True
        )


        reasons = []


        # Get top features

        for feature, importance_value in (
            feature_pairs[:top_n]
        ):

            feature_index = (
                feature_names.index(
                    feature
                )
            )

            value = float(
                X_scaled[
                    0
                ][
                    feature_index
                ]
            )


            reasons.append({

                "feature":
                    feature,

                "value":
                    value,

                "importance":
                    float(
                        importance_value
                    ),

                "explanation": (
                    f"{feature} is one of the "
                    f"features the trained model "
                    f"considers important when "
                    f"distinguishing network "
                    f"traffic classes."
                )
            })


        return reasons


    except Exception as error:

        print(
            "Feature importance explanation failed:"
        )

        print(error)

        return [
            {
                "feature": "N/A",
                "value": 0.0,
                "importance": 0.0,
                "explanation":
                    "Feature explanation unavailable."
            }
        ]


# ============================================================
# MULTICLASS PREDICTION
# ============================================================

def predict_multiclass(
    features
):

    # --------------------------------------------------------
    # Validate input
    # --------------------------------------------------------

    validate_features(
        features
    )


    # --------------------------------------------------------
    # Convert dictionary to DataFrame
    # --------------------------------------------------------

    X = prepare_features(
        features,
        multiclass_scaler
    )


    # --------------------------------------------------------
    # Scale features
    # --------------------------------------------------------

    X_scaled = (
        multiclass_scaler.transform(
            X
        )
    )


    # --------------------------------------------------------
    # Get probability for every class
    # --------------------------------------------------------

    probabilities = (
        multiclass_model.predict_proba(
            X_scaled
        )[0]
    )


    # --------------------------------------------------------
    # Find class with highest probability
    # --------------------------------------------------------

    predicted_index = int(
        probabilities.argmax()
    )


    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    confidence = float(
        probabilities[
            predicted_index
        ]
    )


    # --------------------------------------------------------
    # Convert class index to attack name
    # --------------------------------------------------------

    predicted_label = (
        label_encoder.inverse_transform(
            [predicted_index]
        )[0]
    )

    predicted_label = str(
        predicted_label
    )


    # --------------------------------------------------------
    # Attack explanation
    # --------------------------------------------------------

    attack_explanation = (
        get_attack_explanation(
            predicted_label
        )
    )


    # --------------------------------------------------------
    # Important features
    # --------------------------------------------------------

    reasons = get_feature_reasons(
        X_scaled,
        top_n=5
    )


    # ========================================================
    # BUILD JSON OBJECT
    # ========================================================

    result = {

        "prediction":
            predicted_label,

        "confidence":
            confidence,

        "attack_explanation":
            attack_explanation,

        "reasons":
            reasons,

        "model":
            "xgboost_multiclass"
    }


    # ========================================================
    # CONVERT TO JSON
    # ========================================================

    return json.dumps(
        result,
        indent=4
    )


# ============================================================
# MAIN PREDICTION INTERFACE
# ============================================================

def predict(
    features
):

    return predict_multiclass(
        features
    )