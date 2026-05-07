import random
import time


normal_logs = [
    '192.168.1.10 - - [07/May/2026:20:00:01] "GET /home HTTP/1.1" 200',
    '192.168.1.11 - - [07/May/2026:20:00:02] "GET /about HTTP/1.1" 200',
    '192.168.1.12 - - [07/May/2026:20:00:03] "POST /login HTTP/1.1" 200'
]


attack_logs = [
    '192.168.1.99 - - [07/May/2026:20:01:01] "POST /login HTTP/1.1" 401',
    '192.168.1.99 - - [07/May/2026:20:01:02] "POST /login HTTP/1.1" 401',
    '192.168.1.99 - - [07/May/2026:20:01:03] "POST /login HTTP/1.1" 401',
    '192.168.1.150 - - [07/May/2026:20:02:01] "GET /index.php?id=\' OR 1=1 -- HTTP/1.1" 200'
]


def generate_logs():

    while True:

        log_type = random.choice(["normal", "attack"])

        if log_type == "normal":
            log = random.choice(normal_logs)

        else:
            log = random.choice(attack_logs)

        with open("logs/sample.log", "a") as file:
            file.write(log + "\n")

        print(f"Generated log: {log}")

        time.sleep(3)


if __name__ == "__main__":
    generate_logs()