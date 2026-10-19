from __future__ import annotations

from .anomaly import detect_anomalies
from .models import Event, Finding
from .parsers import detect_format, parse_ssh, parse_web
from .rules import Config, run_rules


def analyze(events: list[Event], cfg: Config | None = None, use_ml: bool = True):
    findings = run_rules(events, cfg)
    notes: list[str] = []
    if use_ml:
        ml, notes = detect_anomalies(events)
        findings += ml
    return findings, notes


__all__ = ["analyze", "Event", "Finding", "Config", "parse_ssh", "parse_web", "detect_format"]
