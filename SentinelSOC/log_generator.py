import random
import time
from datetime import datetime


# =====================================
# CONFIGURATION
# =====================================

LOG_FILE = "logs/sample.log"


# =====================================
# NORMAL TRAFFIC
# =====================================

normal_endpoints = [

    "/home",
    "/about",
    "/products",
    "/dashboard",
    "/contact",
    "/api/data",
    "/search?q=laptop"

]

normal_ips = [

    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12",
    "192.168.1.13",
    "192.168.1.14"

]


# =====================================
# ATTACK PAYLOADS
# =====================================

sql_payloads = [

    "/index.php?id=' OR 1=1 --",

    "/login.php?user=admin'--",

    "/products?id=1 UNION SELECT password FROM users",

]

admin_payloads = [

    "/admin",
    "/admin/login",
    "/wp-admin",
    "/administrator"

]

attack_ips = [

    "192.168.1.99",
    "192.168.1.150",
    "192.168.1.200"

]


# =====================================
# GENERATE TIMESTAMP
# =====================================

def generate_timestamp():

    return datetime.now().strftime(
        "%d/%b/%Y:%H:%M:%S"
    )


# =====================================
# NORMAL TRAFFIC
# =====================================

def generate_normal_log():

    ip = random.choice(normal_ips)

    endpoint = random.choice(
        normal_endpoints
    )

    timestamp = generate_timestamp()

    return (

        f'{ip} - - '

        f'[{timestamp}] '

        f'"GET {endpoint} HTTP/1.1" 200'

    )


# =====================================
# FAILED LOGIN ATTACK
# =====================================

def generate_failed_login():

    ip = random.choice(attack_ips)

    timestamp = generate_timestamp()

    return (

        f'{ip} - - '

        f'[{timestamp}] '

        f'"POST /login HTTP/1.1" 401'

    )


# =====================================
# SQL INJECTION ATTACK
# =====================================

def generate_sql_injection():

    ip = random.choice(attack_ips)

    payload = random.choice(
        sql_payloads
    )

    timestamp = generate_timestamp()

    return (

        f'{ip} - - '

        f'[{timestamp}] '

        f'"GET {payload} HTTP/1.1" 200'

    )


# =====================================
# ADMIN PROBE ATTACK
# =====================================

def generate_admin_probe():

    ip = random.choice(attack_ips)

    endpoint = random.choice(
        admin_payloads
    )

    timestamp = generate_timestamp()

    return (

        f'{ip} - - '

        f'[{timestamp}] '

        f'"GET {endpoint} HTTP/1.1" 403'

    )


# =====================================
# MAIN LOG GENERATOR
# =====================================

def generate_logs():

    print("Starting live log generation...\n")

    while True:

        # ---------------------------------
        # REALISTIC TRAFFIC DISTRIBUTION
        # ---------------------------------
        traffic_type = random.choices(

            [

                "normal",
                "failed_login",
                "sql_injection",
                "admin_probe"

            ],

            weights=[70, 15, 10, 5],

            k=1

        )[0]

        # ---------------------------------
        # GENERATE LOG
        # ---------------------------------
        if traffic_type == "normal":

            log = generate_normal_log()

        elif traffic_type == "failed_login":

            log = generate_failed_login()

        elif traffic_type == "sql_injection":

            log = generate_sql_injection()

        else:

            log = generate_admin_probe()

        # ---------------------------------
        # WRITE TO LOG FILE
        # ---------------------------------
        with open(LOG_FILE, "a") as file:

            file.write(log + "\n")

        print(f"[+] Generated: {log}")

        # ---------------------------------
        # RANDOM DELAY
        # ---------------------------------
        time.sleep(

            random.randint(1, 4)

        )


# =====================================
# ENTRY POINT
# =====================================

if __name__ == "__main__":

    generate_logs()