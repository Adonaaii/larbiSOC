from flask import Flask, render_template

from analyzer import analyze_logs

app = Flask(__name__)


@app.route("/")
def home():

    alerts = analyze_logs()

    return render_template("dashboard.html", alerts=alerts)


if __name__ == "__main__":
    app.run(debug=True)