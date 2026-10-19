from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone

from ..mitre import attack_label
from .models import Finding, SEVERITY_ORDER

WEIGHT = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 3, "INFO": 0}
COLOR = {"CRITICAL": "\033[1;41m", "HIGH": "\033[1;31m", "MEDIUM": "\033[1;33m", "LOW": "\033[36m", "INFO": "\033[2m"}
RESET = "\033[0m"


def risk_by_ip(findings: list[Finding]) -> list[tuple[str, int, list[Finding]]]:
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        grouped[f.ip].append(f)
    ranked = [(ip, min(100, sum(WEIGHT[f.severity] for f in fs)), fs) for ip, fs in grouped.items()]
    return sorted(ranked, key=lambda r: -r[1])


def to_console(findings, n_events, notes, color=True) -> str:
    c = (lambda s, sev: f"{COLOR[sev]} {s} {RESET}") if color else (lambda s, sev: f"[{s}]")
    out = [f"SentinelAI log analysis - {n_events} events, {len(findings)} findings", ""]
    for ip, score, fs in risk_by_ip(findings):
        out.append(f"{ip:<18} risk {score:>3}/100")
        for f in sorted(fs, key=lambda x: -SEVERITY_ORDER[x.severity]):
            out.append(f"  {c(f.severity, f.severity)} {f.title}")
            out.append(f"      {f.description}")
            if f.technique:
                out.append(f"      ATT&CK: {attack_label(f.technique)}")
            for ev in f.evidence[:3]:
                out.append(f"      > {ev}")
        out.append("")
    out += [f"note: {n}" for n in notes]
    return "\n".join(out)


def to_json(findings, n_events, notes) -> str:
    return json.dumps({
        "generated": datetime.now(timezone.utc).isoformat(), "events": n_events, "notes": notes,
        "ips": [{"ip": ip, "risk": score, "findings": [f.to_dict() for f in fs]}
                for ip, score, fs in risk_by_ip(findings)]}, indent=2)


def to_markdown(findings, n_events, notes) -> str:
    lines = ["# SentinelAI Incident Report", "",
             f"*{n_events} events analysed - {len(findings)} findings*", "",
             "| Source IP | Risk | Findings | ATT&CK |", "|---|---|---|---|"]
    for ip, score, fs in risk_by_ip(findings):
        techs = ", ".join(sorted({f.technique for f in fs if f.technique})) or "-"
        lines.append(f"| `{ip}` | {score} | {', '.join(sorted({f.title for f in fs}))} | {techs} |")
    lines += ["", "## Details", ""]
    for ip, score, fs in risk_by_ip(findings):
        lines.append(f"### {ip} (risk {score}/100)")
        for f in sorted(fs, key=lambda x: -SEVERITY_ORDER[x.severity]):
            lines.append(f"- **{f.severity}** - {f.title}: {f.description} _{attack_label(f.technique)}_")
        lines.append("")
    lines += [f"> {n}" for n in notes]
    return "\n".join(lines)
