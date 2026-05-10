def parse_log(log_line):

    parts = log_line.split()

    ip_address = parts[0]

    status_code = parts[-1]

    return {
        "ip": ip_address,
        "status": status_code,
        "raw": log_line
    }

def generate_statistics(alerts):

    stats = {
        "total_alerts": len(alerts),
        "high_alerts": 0,
        "medium_alerts": 0,
        "low_alerts": 0,
        "unique_ips": set()
    }

    for alert in alerts:

        severity = alert["severity"]

        if severity == "HIGH":
            stats["high_alerts"] += 1

        elif severity == "MEDIUM":
            stats["medium_alerts"] += 1

        elif severity == "LOW":
            stats["low_alerts"] += 1

        stats["unique_ips"].add(alert["ip"])

    stats["unique_ips"] = len(stats["unique_ips"])

    return stats

def generate_ip_leaderboard(alerts):

    ip_counts = {}

    for alert in alerts:

        ip = alert["ip"]

        if ip not in ip_counts:
            ip_counts[ip] = 0

        ip_counts[ip] += 1

    sorted_ips = sorted(
        ip_counts.items(),
        key=lambda item: item[1],
        reverse=True
    )

    return sorted_ips

def generate_ip_leaderboard(alerts):

    # Dictionary to count how many alerts each IP generated
    ip_count = {}

    # Loop through every alert
    for alert in alerts:

        # Extract IP address from alert object
        ip = alert["ip"]

        # If IP has not been seen before,
        # initialize its counter at 0
        if ip not in ip_count:
            ip_count[ip] = 0

        # Increase alert count for this IP
        ip_count[ip] += 1

    # Sort IPs by alert count in descending order
    # Example:
    # ("192.168.1.99", 17)
    # ("192.168.1.15", 4)
    leaderboard = sorted(

        # Convert dictionary into list of tuples
        ip_count.items(),

        # Sort using the second value in each tuple
        # x[0] = IP address
        # x[1] = alert count
        key=lambda x: x[1],

        # Highest counts first
        reverse=True
    )

    return leaderboard