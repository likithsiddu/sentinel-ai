"""Signature / threshold detections. Each rule maps to a MITRE ATT&CK technique."""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta

from .models import Event, Finding
from .parsers import decode_path


@dataclass
class Config:
    ssh_fail_threshold: int = 5          # failures inside window -> brute force
    ssh_window: int = 300                # seconds
    spray_users: int = 8                 # distinct usernames from one IP
    spray_window: int = 1800
    scan_404_threshold: int = 15         # 404s from one IP
    sig_hit_threshold: int = 1           # attack-signature requests


SIGNATURES = {
    "SQL injection": re.compile(
        r"(union(\s|\+|/\*.*?\*/)+(all\s+)?select|\bor\s+1\s*=\s*1|'\s*or\s*'|sleep\(\d+\)|"
        r"information_schema|benchmark\(|;\s*drop\s+table|extractvalue\()", re.I),
    "Cross-site scripting": re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=|<svg[^>]*on)", re.I),
    "Path traversal": re.compile(r"(\.\./|\.\.\\|/etc/passwd|/proc/self/|boot\.ini)", re.I),
    "Command injection / RCE": re.compile(
        r"(\$\{jndi:|(;|\||`|\$\()\s*(cat|ls|id|wget|curl|nc|bash|sh)\b|/bin/(ba)?sh|\bcmd=)", re.I),
}

SENSITIVE_PATHS = re.compile(
    r"(/\.env|/\.git/|/\.aws/|/wp-login\.php|/xmlrpc\.php|/phpmyadmin|/server-status|/actuator|/\.ssh/)", re.I)

SCANNER_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|hydra|zgrab|nuclei|acunetix|nessus)", re.I)


def _max_window(times, seconds: int):
    """Largest number of events inside any sliding window; returns (count, start, end)."""
    times = sorted(times)
    best = (0, None, None)
    j = 0
    for i, t in enumerate(times):
        while t - times[j] > timedelta(seconds=seconds):
            j += 1
        if i - j + 1 > best[0]:
            best = (i - j + 1, times[j], t)
    return best


def web_attack_hits(ev: Event) -> list[str]:
    if ev.source != "web" or not ev.path:
        return []
    target = decode_path(ev.path)
    return [name for name, rx in SIGNATURES.items() if rx.search(target)]


def run_rules(events: list[Event], cfg: Config | None = None) -> list[Finding]:
    cfg = cfg or Config()
    findings: list[Finding] = []
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        by_ip[e.ip].append(e)

    for ip, evs in by_ip.items():
        findings += _ssh_rules(ip, [e for e in evs if e.source == "ssh"], cfg)
        findings += _web_rules(ip, [e for e in evs if e.source == "web"], cfg)
    return findings


def _ssh_rules(ip, evs, cfg) -> list[Finding]:
    out: list[Finding] = []
    fails = [e for e in evs if e.action == "failed"]
    if not fails:
        return out

    count, start, end = _max_window([e.ts for e in fails], cfg.ssh_window)
    users = {e.user for e in fails}
    if count >= cfg.ssh_fail_threshold and len(users) < cfg.spray_users:
        out.append(Finding(
            "SSH-BRUTE-FORCE", "HIGH", ip, "SSH brute-force attack",
            f"{count} failed logins within {cfg.ssh_window // 60} min targeting {len(users)} account(s).",
            "T1110.001", count, start, end,
            [f"targets: {', '.join(sorted(users)[:6])}"]))

    s_count, s_start, s_end = _max_window([e.ts for e in fails], cfg.spray_window)
    if len(users) >= cfg.spray_users and s_count >= cfg.spray_users:
        out.append(Finding(
            "SSH-PASSWORD-SPRAY", "HIGH", ip, "Password spraying",
            f"{len(users)} distinct usernames tried from one source ({len(fails)} failures).",
            "T1110.003", len(fails), s_start, s_end,
            [f"sample users: {', '.join(sorted(users)[:8])}"]))

    # Success after a burst of failures = likely compromised account.
    for ok in (e for e in evs if e.action == "accepted"):
        prior = [f for f in fails if timedelta(0) <= ok.ts - f.ts <= timedelta(seconds=cfg.ssh_window)]
        if len(prior) >= cfg.ssh_fail_threshold:
            out.append(Finding(
                "SSH-SUCCESS-AFTER-BRUTE", "CRITICAL", ip, "Successful login after brute-force burst",
                f"Account '{ok.user}' logged in after {len(prior)} failures from the same IP. "
                "Treat as likely compromised: rotate credentials, kill sessions, review activity.",
                "T1078", len(prior), prior[0].ts, ok.ts, [f"accepted login for '{ok.user}'"]))
            break
    return out


def _web_rules(ip, evs, cfg) -> list[Finding]:
    out: list[Finding] = []
    if not evs:
        return out

    hits: dict[str, list[Event]] = defaultdict(list)
    for e in evs:
        for name in web_attack_hits(e):
            hits[name].append(e)
    for name, es in hits.items():
        if len(es) >= cfg.sig_hit_threshold:
            # An *attempt* is HIGH; CRITICAL is reserved for confirmed compromise (see SSH rules).
            tech = "T1190"
            out.append(Finding(
                f"WEB-{name.split()[0].upper()}", "HIGH", ip, f"{name} attempt",
                f"{len(es)} request(s) matched {name} signatures.", tech, len(es),
                es[0].ts, es[-1].ts, [decode_path(es[0].path)[:120]]))

    not_found = [e for e in evs if e.status == 404]
    if len(not_found) >= cfg.scan_404_threshold:
        distinct = len({e.path for e in not_found})
        out.append(Finding(
            "WEB-FORCED-BROWSING", "MEDIUM", ip, "Directory / endpoint enumeration",
            f"{len(not_found)} 404 responses across {distinct} unique paths.", "T1595.003",
            len(not_found), not_found[0].ts, not_found[-1].ts,
            [e.path for e in not_found[:3]]))

    probes = [e for e in evs if SENSITIVE_PATHS.search(decode_path(e.path or ""))]
    if probes:
        out.append(Finding(
            "WEB-SENSITIVE-PROBE", "MEDIUM", ip, "Probe for sensitive files / admin panels",
            f"{len(probes)} request(s) for sensitive paths.", "T1083", len(probes),
            probes[0].ts, probes[-1].ts, sorted({e.path for e in probes})[:5]))

    scanner = [e for e in evs if SCANNER_UA.search(e.user_agent or "")]
    if scanner:
        tool = SCANNER_UA.search(scanner[0].user_agent).group(1).lower()
        out.append(Finding(
            "WEB-SCANNER-UA", "MEDIUM", ip, f"Automated scanner detected ({tool})",
            f"{len(scanner)} request(s) carried a known offensive-tool user-agent.", "T1595.002",
            len(scanner), scanner[0].ts, scanner[-1].ts, [scanner[0].user_agent[:100]]))
    return out
