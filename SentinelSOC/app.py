from flask import Flask, render_template

from analyzer import analyze_logs

from utils import (
    generate_statistics,
    generate_ip_leaderboard
)

app = Flask(__name__)


@app.route("/")
def home():

    # =====================================
    # GET ALERTS + INCIDENTS
    # =====================================
    alerts, incidents = analyze_logs()

    # =====================================
    # SORT INCIDENTS BY SEVERITY
    # =====================================
    severity_order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1
    }

    sorted_incidents = sorted(
        incidents,
        key=lambda incident: severity_order.get(
            incident["severity"],
            0
        ),
        reverse=True
    )

    # =====================================
    # LIMIT ALERTS SHOWN
    # =====================================
    alerts = alerts[:50]

    # =====================================
    # GENERATE DASHBOARD STATS
    # =====================================
    stats = generate_statistics(alerts)

    # =====================================
    # GENERATE IP LEADERBOARD
    # =====================================
    leaderboard = generate_ip_leaderboard(
        alerts
    )

    # =====================================
    # RENDER DASHBOARD
    # =====================================
    return render_template(
        "dashboard.html",
        alerts=alerts,
        incidents=sorted_incidents,
        stats=stats,
        leaderboard=leaderboard
    )


if __name__ == "__main__":

    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000
    )