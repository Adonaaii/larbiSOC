from flask import Flask, render_template

from analyzer import analyze_logs
from utils import generate_statistics, generate_ip_leaderboard


app = Flask(__name__)


@app.route("/")
def home():

    alerts = analyze_logs()

    stats = generate_statistics(alerts)

    leaderboard = generate_ip_leaderboard(alerts)

    return render_template(
        "dashboard.html",
        alerts=alerts,
        stats=stats,
        leaderboard=leaderboard
    )


if __name__ == "__main__":
    app.run(debug=True)