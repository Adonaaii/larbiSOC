def detect_failed_login(log_line):

    if "401" in log_line:
        return True

    return False

def detect_sql_injection(log_line):

    suspicious_patterns = [
        "OR 1=1",
        "'--",
        "UNION SELECT",
        "DROP TABLE"
    ]

    for pattern in suspicious_patterns:

        if pattern in log_line:
            return True

    return False

def detect_admin_probe(log_line):

    if "/admin" in log_line and "403" in log_line:
        return True

    return False

def detect_brute_force(failed_logins, ip_address):

    if failed_logins[ip_address] >= 3:
        return True

    return False