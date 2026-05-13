from rules import (
    detect_failed_login,
    detect_sql_injection,
    detect_admin_probe,
    detect_brute_force
)

from utils import parse_log
from storage import save_alert
from datetime import datetime
from ai_analyst import generate_ai_summary


def calculate_threat_score(incident):

    score = 0

    # =====================================
    # FAILED LOGIN SCORING
    # =====================================

    if incident["failed_logins"] >= 5:

        score += 40

    # =====================================
    # SQL INJECTION SCORING
    # =====================================

    if incident["sql_injection"]:

        score += 50

    # =====================================
    # ADMIN PROBE / SCANNER SCORING
    # =====================================

    if incident["scanner_activity"]:

        score += 30

    return min(score, 100)


def determine_severity(score):

    if score >= 80:

        return "CRITICAL"

    elif score >= 50:

        return "HIGH"

    elif score >= 25:

        return "MEDIUM"

    return "LOW"


def analyze_logs():

    alerts = []

    incidents = {}

    failed_logins = {}

    processed_logs = set()

    # =====================================
    # READ LOG FILE
    # =====================================

    with open("logs/sample.log", "r") as file:

        logs = file.readlines()

    # =====================================
    # PROCESS LOGS
    # =====================================

    for line in logs:

        line = line.strip()

        # =====================================
        # SKIP DUPLICATE LOGS
        # =====================================

        if line in processed_logs:

            continue

        processed_logs.add(line)

        # =====================================
        # PARSE LOG
        # =====================================

        parsed_log = parse_log(line)

        ip = parsed_log["ip"]

        current_time = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        # =====================================
        # CREATE INCIDENT OBJECT
        # =====================================

        if ip not in incidents:

            incidents[ip] = {

                "ip": ip,

                "failed_logins": 0,

                "sql_injection": False,

                "scanner_activity": False,

                "score": 0,

                "severity": "LOW",

                "status": "MONITORING",

                "primary_attack": "Unknown",

                "ai_generated": False,

                "ai_summary": "",

                "event_count": 0,

                "attack_types": [],

                "first_seen": current_time,

                "last_seen": current_time,

                "duration": "0s",

                "latest_log": "",

                "status": "ACTIVE"
            }

        # =====================================
        # UPDATE INCIDENT ACTIVITY
        # =====================================

        incidents[ip]["last_seen"] = current_time

        incidents[ip]["latest_log"] = line

        # =====================================
        # CALCULATE INCIDENT DURATION
        # =====================================

        first_seen_time = datetime.strptime(
            incidents[ip]["first_seen"],
            "%Y-%m-%d %H:%M:%S"
        )

        last_seen_time = datetime.strptime(
            incidents[ip]["last_seen"],
            "%Y-%m-%d %H:%M:%S"
        )

        duration = (
            last_seen_time - first_seen_time
        )

        incidents[ip]["duration"] = str(
            duration
        )

        # =====================================
        # TRACK FAILED LOGINS
        # =====================================

        if ip not in failed_logins:

            failed_logins[ip] = 0

        # =====================================
        # FAILED LOGIN DETECTION
        # =====================================

        if detect_failed_login(line):

            failed_logins[ip] += 1

            incidents[ip]["failed_logins"] += 1

            incidents[ip]["event_count"] += 1

            incidents[ip]["primary_attack"] = (
                "Credential Attack"
            )

            if (
                "Failed Login"
                not in incidents[ip]["attack_types"]
            ):

                incidents[ip]["attack_types"].append(
                    "Failed Login"
                )

            # =====================================
            # UPDATE THREAT SCORE
            # =====================================

            incidents[ip]["score"] = (
                calculate_threat_score(
                    incidents[ip]
                )
            )

            incidents[ip]["severity"] = (
                determine_severity(
                    incidents[ip]["score"]
                )
            )

            # =====================================
            # UPDATE STATUS
            # =====================================

            if incidents[ip]["severity"] in [
                "HIGH",
                "CRITICAL"
            ]:

                incidents[ip]["status"] = (
                    "ACTIVE THREAT"
                )

            else:

                incidents[ip]["status"] = (
                    "MONITORING"
                )

            # =====================================
            # GENERATE AI SUMMARY ONCE
            # =====================================

            if (
                incidents[ip]["severity"]
                in ["HIGH", "CRITICAL"]

                and not incidents[ip]["ai_generated"]
            ):

                print(
                    f"Generating AI summary "
                    f"for {ip}..."
                )

                incidents[ip]["ai_summary"] = (
                    generate_ai_summary(
                        incidents[ip]
                    )
                )

                incidents[ip]["ai_generated"] = True

            # =====================================
            # CREATE ALERT
            # =====================================

            alert = {

                "timestamp": current_time,

                "severity": (
                    incidents[ip]["severity"]
                ),

                "score": (
                    incidents[ip]["score"]
                ),

                "status": (
                    incidents[ip]["status"]
                ),

                "type": "Failed Login",

                "ip": ip,

                "reason": (
                    "401 Unauthorized detected"
                ),

                "log": line,

                "event_count": (
                    incidents[ip]["event_count"]
                ),

                "attack_types": (
                    incidents[ip]["attack_types"]
                ),

                "primary_attack": (
                    incidents[ip]["primary_attack"]
                ),

                "ai_summary": (
                    incidents[ip]["ai_summary"]
                )
            }

            alerts.append(alert)

            save_alert(alert)

            # =====================================
            # BRUTE FORCE DETECTION
            # =====================================

            if detect_brute_force(
                failed_logins,
                ip
            ):

                incidents[ip]["event_count"] += 1

                incidents[ip]["primary_attack"] = (
                    "Credential Attack"
                )

                if (
                    "Brute Force"
                    not in incidents[ip]["attack_types"]
                ):

                    incidents[ip]["attack_types"].append(
                        "Brute Force"
                    )

                incidents[ip]["score"] = (
                    calculate_threat_score(
                        incidents[ip]
                    )
                )

                incidents[ip]["severity"] = (
                    determine_severity(
                        incidents[ip]["score"]
                    )
                )

                brute_force_alert = {

                    "timestamp": current_time,

                    "severity": (
                        incidents[ip]["severity"]
                    ),

                    "score": (
                        incidents[ip]["score"]
                    ),

                    "status": (
                        incidents[ip]["status"]
                    ),

                    "type": (
                        "Brute Force Attempt"
                    ),

                    "ip": ip,

                    "reason": (
                        f"{failed_logins[ip]} "
                        "failed logins detected"
                    ),

                    "log": line,

                    "event_count": (
                        incidents[ip]["event_count"]
                    ),

                    "attack_types": (
                        incidents[ip]["attack_types"]
                    ),

                    "primary_attack": (
                        incidents[ip]["primary_attack"]
                    ),

                    "ai_summary": (
                        incidents[ip]["ai_summary"]
                    )
                }

                alerts.append(
                    brute_force_alert
                )

                save_alert(
                    brute_force_alert
                )

        # =====================================
        # SQL INJECTION DETECTION
        # =====================================

        elif detect_sql_injection(line):

            incidents[ip]["sql_injection"] = True

            incidents[ip]["event_count"] += 1

            incidents[ip]["primary_attack"] = (
                "Web Application Attack"
            )

            if (
                "SQL Injection"
                not in incidents[ip]["attack_types"]
            ):

                incidents[ip]["attack_types"].append(
                    "SQL Injection"
                )

            incidents[ip]["score"] = (
                calculate_threat_score(
                    incidents[ip]
                )
            )

            incidents[ip]["severity"] = (
                determine_severity(
                    incidents[ip]["score"]
                )
            )

            if incidents[ip]["severity"] in [
                "HIGH",
                "CRITICAL"
            ]:

                incidents[ip]["status"] = (
                    "ACTIVE THREAT"
                )

            else:

                incidents[ip]["status"] = (
                    "MONITORING"
                )

            if (
                incidents[ip]["severity"]
                in ["HIGH", "CRITICAL"]

                and not incidents[ip]["ai_generated"]
            ):

                print(
                    f"Generating AI summary "
                    f"for {ip}..."
                )

                incidents[ip]["ai_summary"] = (
                    generate_ai_summary(
                        incidents[ip]
                    )
                )

                incidents[ip]["ai_generated"] = True

            alert = {

                "timestamp": current_time,

                "severity": (
                    incidents[ip]["severity"]
                ),

                "score": (
                    incidents[ip]["score"]
                ),

                "status": (
                    incidents[ip]["status"]
                ),

                "type": "SQL Injection",

                "ip": ip,

                "reason": (
                    "SQL injection signature "
                    "detected"
                ),

                "log": line,

                "event_count": (
                    incidents[ip]["event_count"]
                ),

                "attack_types": (
                    incidents[ip]["attack_types"]
                ),

                "primary_attack": (
                    incidents[ip]["primary_attack"]
                ),

                "ai_summary": (
                    incidents[ip]["ai_summary"]
                )
            }

            alerts.append(alert)

            save_alert(alert)

        # =====================================
        # ADMIN PROBE DETECTION
        # =====================================

        elif detect_admin_probe(line):

            incidents[ip]["scanner_activity"] = True

            incidents[ip]["event_count"] += 1

            incidents[ip]["primary_attack"] = (
                "Reconnaissance Activity"
            )

            if (
                "Admin Probe"
                not in incidents[ip]["attack_types"]
            ):

                incidents[ip]["attack_types"].append(
                    "Admin Probe"
                )

            incidents[ip]["score"] = (
                calculate_threat_score(
                    incidents[ip]
                )
            )

            incidents[ip]["severity"] = (
                determine_severity(
                    incidents[ip]["score"]
                )
            )

            if incidents[ip]["severity"] in [
                "HIGH",
                "CRITICAL"
            ]:

                incidents[ip]["status"] = (
                    "ACTIVE THREAT"
                )

            else:

                incidents[ip]["status"] = (
                    "MONITORING"
                )

            if (
                incidents[ip]["severity"]
                in ["HIGH", "CRITICAL"]

                and not incidents[ip]["ai_generated"]
            ):

                print(
                    f"Generating AI summary "
                    f"for {ip}..."
                )

                incidents[ip]["ai_summary"] = (
                    generate_ai_summary(
                        incidents[ip]
                    )
                )

                incidents[ip]["ai_generated"] = True

            alert = {

                "timestamp": current_time,

                "severity": (
                    incidents[ip]["severity"]
                ),

                "score": (
                    incidents[ip]["score"]
                ),

                "status": (
                    incidents[ip]["status"]
                ),

                "type": "Admin Probe",

                "ip": ip,

                "reason": (
                    "Forbidden admin "
                    "access attempt"
                ),

                "log": line,

                "event_count": (
                    incidents[ip]["event_count"]
                ),

                "attack_types": (
                    incidents[ip]["attack_types"]
                ),

                "primary_attack": (
                    incidents[ip]["primary_attack"]
                ),

                "ai_summary": (
                    incidents[ip]["ai_summary"]
                )
            }

            alerts.append(alert)

            save_alert(alert)

    # =====================================
    # SORT ALERTS BY THREAT SCORE
    # =====================================

    alerts = sorted(

        alerts,

        key=lambda alert: (
            alert["score"]
        ),

        reverse=True
    )

    # =====================================
    # SORT INCIDENTS BY SCORE
    # =====================================

    sorted_incidents = sorted(

        incidents.values(),

        key=lambda incident: (
            incident["score"]
        ),

        reverse=True
    )

    return alerts, sorted_incidents


if __name__ == "__main__":

    alerts, incidents = analyze_logs()

    print(
        f"\nTotal alerts generated: "
        f"{len(alerts)}\n"
    )

    print(
        f"Total incidents tracked: "
        f"{len(incidents)}\n"
    )

    for alert in alerts[:10]:

        print(alert)

        print("-" * 80)