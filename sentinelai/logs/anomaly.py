"""Behavioural anomaly detection with Isolation Forest.

Rules only catch attacks someone already wrote a rule for. This module profiles every source IP
and flags behaviour that is statistically unlike the rest of the population - low-and-slow
scanners, odd error patterns, unusual breadth - then *explains* the flag using robust z-scores
so an analyst can see why, instead of trusting an opaque score.
"""
from __future__ import annotations

from collections import defaultdict

import numpy as np
from sklearn.ensemble import IsolationForest

from .models import Event, Finding
from .rules import SCANNER_UA, web_attack_hits

FEATURES = [
    "events", "ssh_fail_ratio", "distinct_users", "distinct_paths",
    "err_4xx_ratio", "err_5xx_ratio", "events_per_min", "attack_sig_hits", "scanner_ua",
]
MIN_SOURCES = 12   # an unsupervised model needs a population to compare against


def build_features(events: list[Event]) -> tuple[list[str], np.ndarray]:
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        by_ip[e.ip].append(e)

    ips, rows = [], []
    for ip, evs in sorted(by_ip.items()):
        ssh = [e for e in evs if e.source == "ssh" and e.action in ("failed", "accepted")]
        web = [e for e in evs if e.source == "web"]
        span_min = max((max(e.ts for e in evs) - min(e.ts for e in evs)).total_seconds() / 60, 1.0)
        rows.append([
            len(evs),
            (sum(e.action == "failed" for e in ssh) / len(ssh)) if ssh else 0.0,
            len({e.user for e in evs if e.user}),
            len({e.path for e in web}),
            (sum(400 <= (e.status or 0) < 500 for e in web) / len(web)) if web else 0.0,
            (sum((e.status or 0) >= 500 for e in web) / len(web)) if web else 0.0,
            len(evs) / span_min,
            sum(bool(web_attack_hits(e)) for e in web),
            float(any(SCANNER_UA.search(e.user_agent or "") for e in web)),
        ])
        ips.append(ip)
    return ips, np.array(rows, dtype=float)


def _robust_z(X: np.ndarray) -> np.ndarray:
    med = np.median(X, axis=0)
    mad = np.median(np.abs(X - med), axis=0)
    scale = np.where(mad < 1e-9, np.maximum(X.std(axis=0), 1e-9), 1.4826 * mad)
    return (X - med) / scale


def detect_anomalies(events: list[Event], seed: int = 42, z_gate: float = 3.5):
    """Returns (findings, notes). Gate: flagged by the forest AND at least one feature is a
    strong outlier - this keeps false positives down on small / quiet populations."""
    ips, X = build_features(events)
    if len(ips) < MIN_SOURCES:
        return [], [f"Anomaly model skipped: only {len(ips)} sources (need >= {MIN_SOURCES})."]

    model = IsolationForest(n_estimators=300, contamination="auto", random_state=seed)
    model.fit(X)
    labels = model.predict(X)
    scores = -model.score_samples(X)          # higher = more anomalous
    Z = _robust_z(X)

    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        by_ip[e.ip].append(e)

    findings: list[Finding] = []
    for i, ip in enumerate(ips):
        if labels[i] != -1:
            continue
        order = np.argsort(-Z[i])[:3]
        reasons = [f"{FEATURES[j]}={X[i][j]:.2f} ({Z[i][j]:+.1f} sigma vs peers)"
                   for j in order if Z[i][j] >= z_gate]
        if not reasons:
            continue
        evs = by_ip[ip]
        findings.append(Finding(
            "ML-BEHAVIOUR-ANOMALY", "MEDIUM", ip, "Behavioural outlier (Isolation Forest)",
            f"Anomaly score {scores[i]:.3f}. Behaviour differs sharply from the other "
            f"{len(ips) - 1} sources.", None, len(evs),
            min(e.ts for e in evs), max(e.ts for e in evs), reasons))
    return findings, [f"Isolation Forest profiled {len(ips)} sources across {len(FEATURES)} features."]
