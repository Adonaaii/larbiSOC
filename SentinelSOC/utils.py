def parse_log(log_line):

    parts = log_line.split()

    ip_address = parts[0]

    status_code = parts[-1]

    return {
        "ip": ip_address,
        "status": status_code,
        "raw": log_line
    }