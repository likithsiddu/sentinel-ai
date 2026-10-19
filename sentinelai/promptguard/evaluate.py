"""Reproducible evaluation: python -m sentinelai prompt eval"""
from __future__ import annotations

from . import dataset
from .scanner import BLOCK, REVIEW, scan


def _m(rows, key, thr):
    tp = sum(1 for y, r in rows if y and r[key] >= thr)
    fp = sum(1 for y, r in rows if not y and r[key] >= thr)
    fn = sum(1 for y, r in rows if y and r[key] < thr)
    tn = sum(1 for y, r in rows if not y and r[key] < thr)
    p = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * rc / (p + rc) if p + rc else 0.0
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=p, recall=rc, f1=f1)


def run(verbose: bool = True) -> dict:
    rows = []
    for text, y in dataset.HELD_OUT:
        r = scan(text)
        rows.append((y, {"heuristic": r.heuristic_score, "ml": r.ml_score, "ensemble": r.score}, text, r))
    pairs = [(y, s) for y, s, _, _ in rows]
    thresholds = {"heuristic": 0.5, "ml": 0.5, "ensemble": REVIEW}
    results = {k: _m(pairs, k, t) for k, t in thresholds.items()}
    results["ensemble@BLOCK"] = _m(pairs, "ensemble", BLOCK)
    if verbose:
        print(f"Held-out set: {len(rows)} prompts "
              f"({sum(y for y, *_ in rows)} malicious / {sum(1 - y for y, *_ in rows)} benign)\n")
        print(f"{'detector':<18}{'precision':>10}{'recall':>9}{'F1':>7}{'FP':>5}{'FN':>5}")
        for k, m in results.items():
            print(f"{k:<18}{m['precision']:>10.3f}{m['recall']:>9.3f}{m['f1']:>7.3f}{m['fp']:>5}{m['fn']:>5}")
        print("\nErrors (ensemble @ REVIEW threshold):")
        for y, s, text, r in rows:
            if (s["ensemble"] >= REVIEW) != bool(y):
                kind = "MISSED " if y else "FALSE+ "
                print(f"  {kind} score={s['ensemble']:.2f}  {text[:85]}")
    return results
