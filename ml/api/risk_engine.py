# =========================================================
# RISK ENGINE
# =========================================================


def calculate_risk(
    attack_probability,
    is_anomaly
):
    """
    Combine XGBoost and Isolation Forest results
    into a simple application-level risk level.
    """

    # -----------------------------------------------------
    # HIGH RISK
    # -----------------------------------------------------

    if attack_probability >= 0.80:

        return "HIGH"


    # -----------------------------------------------------
    # MEDIUM RISK
    # -----------------------------------------------------

    if attack_probability >= 0.20:

        return "MEDIUM"


    # Isolation Forest detected unusual behaviour
    if is_anomaly:

        return "MEDIUM"


    # -----------------------------------------------------
    # LOW RISK
    # -----------------------------------------------------

    return "LOW"