import json
import os


# =====================================
# STORAGE CONFIGURATION
# =====================================

os.makedirs("data", exist_ok=True)

ALERTS_FILE = "data/alerts.json"


# =====================================
# LOAD ALERTS FROM JSON
# =====================================

def load_alerts():

    # ---------------------------------
    # FILE DOES NOT EXIST
    # ---------------------------------
    if not os.path.exists(ALERTS_FILE):

        return []

    # ---------------------------------
    # LOAD JSON SAFELY
    # ---------------------------------
    try:

        with open(ALERTS_FILE, "r") as file:

            return json.load(file)

    except (
        json.JSONDecodeError,
        FileNotFoundError
    ):

        return []


# =====================================
# SAVE ALERT
# =====================================

def save_alert(alert):

    alerts = load_alerts()

    # =================================
    # PREVENT DUPLICATE ALERTS
    # =================================
    for existing_alert in alerts:

        if (

            existing_alert["ip"]
            == alert["ip"]

            and

            existing_alert["type"]
            == alert["type"]

            and

            existing_alert["log"]
            == alert["log"]

        ):

            # Duplicate found
            return

    # =================================
    # APPEND NEW ALERT
    # =================================
    alerts.append(alert)

    # =================================
    # LIMIT STORED ALERTS
    # =================================
    alerts = alerts[-500:]

    # =================================
    # SAVE TO JSON FILE
    # =================================
    with open(ALERTS_FILE, "w") as file:

        json.dump(
            alerts,
            file,
            indent=4
        )


# =====================================
# CLEAR ALERT STORAGE
# =====================================

def clear_alerts():

    with open(ALERTS_FILE, "w") as file:

        json.dump([], file)