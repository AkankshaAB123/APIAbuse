# =========================================================
# DECISION ENGINE
# =========================================================


def make_decision(
    xgboost_prediction,
    xgboost_attack_probability,
    random_forest_prediction,
    random_forest_attack_probability
):
    """
    Combines XGBoost and Random Forest predictions.

    Both models must agree before declaring an ATTACK.

    If they disagree, the result is UNCERTAIN.
    """

    # =====================================================
    # BOTH MODELS SAY ATTACK
    # =====================================================

    if (
        xgboost_prediction == "ATTACK"
        and random_forest_prediction == "ATTACK"
    ):

        return "ATTACK"


    # =====================================================
    # BOTH MODELS SAY BENIGN
    # =====================================================

    if (
        xgboost_prediction == "BENIGN"
        and random_forest_prediction == "BENIGN"
    ):

        return "BENIGN"


    # =====================================================
    # MODELS DISAGREE
    # =====================================================

    return "UNCERTAIN"