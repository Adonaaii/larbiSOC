from collections import Counter


# =====================================
# PARSE RAW LOG LINE
# =====================================

def parse_log(log_line):

    try:

        parts = log_line.split()

        return {

            "ip": parts[0],

            "status": parts[-1],

            "method": parts[5].replace('"', ''),

            "endpoint": parts[6],

            "raw": log_line

        }

    except Exception:

        # Prevent analyzer crashes
        return {

            "ip": "UNKNOWN",

            "status": "UNKNOWN",

            "method": "UNKNOWN",

            "endpoint": "UNKNOWN",

            "raw": log_line

        }


# =====================================
# GENERATE DASHBOARD STATISTICS
# =====================================

def generate_statistics(alerts):

    stats = {

        "total_alerts": len(alerts),

        "critical_alerts": 0,

        "high_alerts": 0,

        "medium_alerts": 0,

        "low_alerts": 0,

        "unique_ips": set()
    }

    for alert in alerts:

        severity = alert["severity"]

        # -----------------------------
        # COUNT ALERT SEVERITY
        # -----------------------------
        if severity == "CRITICAL":

            stats["critical_alerts"] += 1

        elif severity == "HIGH":

            stats["high_alerts"] += 1

        elif severity == "MEDIUM":

            stats["medium_alerts"] += 1

        elif severity == "LOW":

            stats["low_alerts"] += 1

        # -----------------------------
        # TRACK UNIQUE IPS
        # -----------------------------
        stats["unique_ips"].add(
            alert["ip"]
        )

    # Convert set -> total count
    stats["unique_ips"] = len(
        stats["unique_ips"]
    )

    return stats


# =====================================
# GENERATE IP LEADERBOARD
# =====================================

def generate_ip_leaderboard(alerts):

    ip_counter = Counter()

    for alert in alerts:

        ip_counter[alert["ip"]] += 1

    # Most suspicious IPs first
    leaderboard = ip_counter.most_common(10)

    return leaderboard