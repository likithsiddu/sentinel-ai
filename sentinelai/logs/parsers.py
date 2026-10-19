"""Parsers for OpenSSH (syslog auth.log) and Apache/Nginx combined access logs."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterable, Iterator
from urllib.parse import unquote

from .models import Event

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
SSH_FAILED_RE = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port \d+")
SSH_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port \d+")
SSH_INVALID_RE = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)")

WEB_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: [^"]*)?" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)


def parse_ssh(lines: Iterable[str], year: int | None = None) -> Iterator[Event]:
    year = year or datetime.now().year
    for line in lines:
        m = SYSLOG_RE.match(line.strip())
        if not m:
            continue
        ts = datetime(year, _MONTHS[m["mon"]], int(m["day"]),
                      *map(int, m["time"].split(":")), tzinfo=timezone.utc)
        msg = m["msg"]
        for regex, action in ((SSH_FAILED_RE, "failed"), (SSH_ACCEPTED_RE, "accepted"),
                              (SSH_INVALID_RE, "invalid_user")):
            hit = regex.search(msg)
            if hit:
                yield Event(ts=ts, source="ssh", ip=hit["ip"], action=action, user=hit["user"])
                break


def parse_web(lines: Iterable[str]) -> Iterator[Event]:
    for line in lines:
        m = WEB_RE.match(line.strip())
        if not m:
            continue
        try:
            ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            continue
        size = int(m["size"]) if m["size"].isdigit() else 0
        yield Event(ts=ts, source="web", ip=m["ip"], action="request",
                    user=None if m["user"] == "-" else m["user"], method=m["method"],
                    path=m["path"], status=int(m["status"]), size=size,
                    user_agent=m["ua"] or "")


def detect_format(sample: list[str]) -> str:
    ssh = sum(1 for l in sample if SYSLOG_RE.match(l.strip()))
    web = sum(1 for l in sample if WEB_RE.match(l.strip()))
    if ssh == web == 0:
        return "unknown"
    return "ssh" if ssh >= web else "web"


def decode_path(path: str) -> str:
    """Double URL-decode so %252e%252e%252f style evasions are still matched."""
    return unquote(unquote(path))
