from __future__ import annotations

from dataclasses import dataclass, field

from .patterns import decode_base64_blobs, match_rules, normalize

SIGNAL_WEIGHT = {"unicode_tag_smuggling": 0.90, "zero_width_chars": 0.35,
                 "unicode_homoglyphs_or_fullwidth": 0.30}
# Combiner + thresholds were chosen by 5-fold cross-validation on the TRAIN set only
# (the held-out set is never used for tuning). See docs/EVALUATION.md.
RULE_WEIGHT = 0.30
BLOCK, REVIEW = 0.50, 0.35
HARD_BLOCK_SIGNALS = {"unicode_tag_smuggling"}   # invisible-payload smuggling is never benign


@dataclass
class ScanResult:
    score: float
    verdict: str                       # ALLOW | REVIEW | BLOCK
    heuristic_score: float
    ml_score: float | None
    matches: list[dict] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)
    decoded_payloads: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _noisy_or(ws) -> float:
    p = 1.0
    for w in ws:
        p *= 1 - w
    return 1 - p


def combine(h: float, m: float | None) -> float:
    """Rules are high-recall but context-blind ("explain the 'ignore previous instructions'
    attack" trips them); the ML layer is context-aware. A weighted blend lets each correct the other."""
    return h if m is None else RULE_WEIGHT * h + (1 - RULE_WEIGHT) * m


def scan(text: str, use_ml: bool = True) -> ScanResult:
    norm, signals = normalize(text)
    weights, matches = [], []

    for rule in match_rules(norm):
        weights.append(rule.weight)
        matches.append({"rule": rule.name, "category": rule.category, "weight": rule.weight,
                        "owasp": rule.owasp, "atlas": rule.atlas, "why": rule.why})

    # One level of base64 decoding - attackers hide instructions from naive keyword filters.
    decoded = decode_base64_blobs(text)
    ml_inputs = [norm]
    for payload in decoded:
        pn, _ = normalize(payload)
        ml_inputs.append(pn)
        for rule in match_rules(pn):
            weights.append(min(0.95, rule.weight + 0.1))
            matches.append({"rule": f"{rule.name} (base64-decoded)", "category": rule.category,
                            "weight": rule.weight, "owasp": rule.owasp, "atlas": rule.atlas,
                            "why": "Hidden inside a base64 blob. " + rule.why})
    if decoded:
        signals.append("base64_payload")
    for s in signals:
        weights.append(SIGNAL_WEIGHT.get(s, 0.2))

    h = _noisy_or(weights)
    m = None
    if use_ml:
        from .classifier import ml_probability
        m = max(ml_probability(t) for t in ml_inputs)
    score = combine(h, m)
    if HARD_BLOCK_SIGNALS & set(signals):
        score = max(score, BLOCK)
    verdict = "BLOCK" if score >= BLOCK else "REVIEW" if score >= REVIEW else "ALLOW"
    return ScanResult(round(score, 3), verdict, round(h, 3), None if m is None else round(m, 3),
                      matches, signals, decoded)
