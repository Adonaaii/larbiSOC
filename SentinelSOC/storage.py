import json
import os
os.makedirs("data", exist_ok=True)
ALERTS_FILE = "data/alerts.json"


def load_alerts():

    # If file doesn't exist yet
    if not os.path.exists(ALERTS_FILE):
        return []

    try:
        with open(ALERTS_FILE, "r") as file:
            return json.load(file)

    except json.JSONDecodeError:
        return []


def save_alert(alert):

    # Load existing alerts
    alerts = load_alerts()

    # Add new alert
    alerts.append(alert)

    # Write updated list back
    with open(ALERTS_FILE, "w") as file:
        json.dump(alerts, file, indent=4)