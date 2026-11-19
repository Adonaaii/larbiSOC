# SentinelSOC

A Python and Flask lab for triaging alerts from sample web access logs. The analyzer groups detections by source IP, scores incidents and displays them in a dashboard with alert statistics.

- [Detection rules](SentinelSOC/rules.py)
- [Incident correlation and scoring](SentinelSOC/analyzer.py)
- [Dashboard template](SentinelSOC/templates/dashboard.html)

## Run locally

Use Python 3.12. From the repository root:

```bash
cd SentinelSOC
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
flask --app app run
```

Open `http://127.0.0.1:5000`. The app reads the bundled sample log. When configured with a `GROQ_API_KEY`, the app can send selected incident fields to Groq to generate a summary. Use sample data when trying this feature.
