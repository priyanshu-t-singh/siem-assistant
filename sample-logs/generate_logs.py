#!/usr/bin/env python3
"""
Generate synthetic NGINX combined-format access logs for SIEM testing.
Writes to access.log in the same directory indefinitely.

Usage:
    python generate_logs.py            # loop forever
    python generate_logs.py --count 500  # write N lines and exit
"""

import random
import time
import argparse
from datetime import datetime, timezone

LOG_PATH = "access.log"

NORMAL_IPS = [f"10.0.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(30)]
BAD_IPS = ["185.220.101.5", "45.142.212.100", "91.108.4.213", "198.51.100.99", "203.0.113.42"]

PATHS = [
    "/", "/index.html", "/about", "/contact", "/products", "/api/v1/users",
    "/api/v1/data", "/login", "/logout", "/dashboard", "/static/main.js",
    "/static/style.css", "/favicon.ico", "/robots.txt",
    "/admin", "/wp-login.php", "/.env", "/phpmyadmin", "/api/v1/secret",
]

METHODS = ["GET", "GET", "GET", "GET", "POST", "PUT", "DELETE"]
HTTP_VERSIONS = ["HTTP/1.1", "HTTP/2.0"]

NORMAL_STATUS = [200, 200, 200, 200, 200, 200, 200, 304, 301, 302]
BAD_STATUS = [400, 401, 403, 404, 404, 404, 500, 503]

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0',
    'curl/7.88.1',
    'python-requests/2.31.0',
    'Wget/1.21.4',
    'Go-http-client/1.1',  # scanner-like
    'sqlmap/1.7.11',       # known scanner
    'Nikto/2.1.6',         # known scanner
    '-',                   # empty UA (suspicious)
]

REFERRERS = ["-", "https://google.com", "https://bing.com", "-", "-", "-"]


def nginx_timestamp() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%d/%b/%Y:%H:%M:%S +0000")


def random_bytes(status: int) -> int:
    if status in (301, 302, 304):
        return 0
    if status >= 400:
        return random.randint(150, 800)
    return random.randint(500, 50000)


def make_line(ip: str, is_bad: bool) -> str:
    method = random.choice(METHODS)
    path = random.choice(PATHS)
    if is_bad and random.random() < 0.6:
        path = random.choice(["/admin", "/wp-login.php", "/.env", "/phpmyadmin", "/etc/passwd"])
    version = random.choice(HTTP_VERSIONS)
    status = random.choice(BAD_STATUS if is_bad else NORMAL_STATUS)
    if is_bad and random.random() < 0.3:
        status = random.choice([401, 403])
    size = random_bytes(status)
    referrer = random.choice(REFERRERS)
    ua = random.choice(USER_AGENTS)
    if is_bad:
        ua = random.choice([USER_AGENTS[-1], USER_AGENTS[-2], USER_AGENTS[-3], USER_AGENTS[-4]])
    ts = nginx_timestamp()
    return f'{ip} - - [{ts}] "{method} {path} {version}" {status} {size} "{referrer}" "{ua}"'


def generate(count: int | None = None):
    written = 0
    print(f"Writing logs to {LOG_PATH}. Ctrl-C to stop.")
    with open(LOG_PATH, "a", buffering=1) as f:
        while True:
            # Occasionally burst bad traffic from a known-bad IP
            burst = random.random() < 0.05  # 5% chance of burst
            if burst:
                bad_ip = random.choice(BAD_IPS)
                burst_size = random.randint(10, 30)
                for _ in range(burst_size):
                    line = make_line(bad_ip, is_bad=True)
                    f.write(line + "\n")
                    written += 1
                    if count and written >= count:
                        print(f"Done. Wrote {written} lines.")
                        return
            else:
                # Normal traffic mix: ~85% normal IPs, ~15% bad IPs
                is_bad = random.random() < 0.15
                ip = random.choice(BAD_IPS if is_bad else NORMAL_IPS)
                line = make_line(ip, is_bad=is_bad)
                f.write(line + "\n")
                written += 1
                if count and written >= count:
                    print(f"Done. Wrote {written} lines.")
                    return

            time.sleep(random.uniform(0.05, 0.3))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Synthetic NGINX log generator")
    parser.add_argument("--count", type=int, default=None, help="Lines to generate (default: infinite)")
    args = parser.parse_args()
    generate(count=args.count)
