from rules import (
    detect_failed_login,
    detect_sql_injection,
    detect_admin_probe,
    detect_brute_force
)

from utils import parse_log


def analyze_logs():

    alerts = []

    failed_logins = {}

    with open("logs/sample.log", "r") as file:
        logs = file.readlines()

    for line in logs:

        line = line.strip()

        parsed_log = parse_log(line)

        ip = parsed_log["ip"]

        if ip not in failed_logins:
            failed_logins[ip] = 0

        if detect_failed_login(line):

            failed_logins[ip] += 1

            alert = {
                "severity": "MEDIUM",
                "type": "Failed Login",
                "ip": ip,
                "reason": "401 Unauthorized detected",
                "log": line
            }

            alerts.append(alert)

            if detect_brute_force(failed_logins, ip):

                brute_force_alert = {
                    "severity": "HIGH",
                    "type": "Brute Force Attempt",
                    "ip": ip,
                    "reason": f"{failed_logins[ip]} failed logins detected",
                    "log": line
                }

                alerts.append(brute_force_alert)

        elif detect_sql_injection(line):

            alert = {
                "severity": "HIGH",
                "type": "SQL Injection",
                "ip": ip,
                "reason": "SQL injection signature detected",
                "log": line
            }

            alerts.append(alert)

        elif detect_admin_probe(line):

            alert = {
                "severity": "LOW",
                "type": "Admin Probe",
                "ip": ip,
                "reason": "Forbidden admin access attempt",
                "log": line
            }

            alerts.append(alert)

    return alerts


if __name__ == "__main__":

    alerts = analyze_logs()

    for alert in alerts:
        print(alert)