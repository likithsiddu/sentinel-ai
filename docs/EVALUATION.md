# Evaluation methodology

Numbers in the README are produced by `python -m sentinelai prompt eval` and the test suite.
This page explains how they were obtained and, just as importantly, what they do **not** show.

## Prompt-injection detector

| Item | Detail |
|---|---|
| Training set | 154 prompts (60 injection/jailbreak, 94 benign) in `promptguard/dataset.py` |
| Hard negatives | dozens of benign prompts that *mention* attack vocabulary ("how do I ignore a file in git", "explain SQL injection", "what is a system prompt") |
| Held-out set | 59 prompts (23 malicious / 36 benign), written separately, **never used for fitting or tuning** |
| Obfuscation cases | base64, zero-width characters, full-width Unicode, leetspeak, Spanish |

**Tuning protocol.** The blend weight (30% rules / 70% ML) and the REVIEW / BLOCK thresholds were
chosen with 5-fold cross-validation on the *training* set only. The held-out set was scored once after
those choices were frozen. Tuning on it would have inflated the results.

**Honest observations**

* Rules alone (F1 0.71) are context-blind: they fire on *discussion* of attacks, not just attacks.
* ML alone (F1 0.94) is context-aware but gives no explanation and has no defence against
  invisible-Unicode smuggling.
* The blend matches ML-alone F1 (0.93) on this small set, and adds what a bare classifier cannot:
  per-match explanations with OWASP LLM / MITRE ATLAS labels, deterministic handling of
  obfuscation, and a three-tier verdict (ALLOW / REVIEW / BLOCK).
* 59 samples means wide confidence intervals: one prompt moves precision by ~4 points. Treat these
  as a sanity check of the approach, **not** a production benchmark.
* The training data is small and hand-written. A real deployment should retrain on traffic from its
  own application and on public corpora, then re-evaluate.

**Known gaps (visible in the eval output)**

* Pure paraphrase attacks with no trigger vocabulary ("set aside the guidance you started with…")
  score in the REVIEW band but fall short of BLOCK.
* Instruction-heavy benign text ("summarise the safety instructions on this fire extinguisher") can
  false-positive.
* Single-turn only: multi-turn "crescendo" attacks are out of scope.
* Detection is a **layer**, not a guarantee. Combine with least-privilege tool access, output
  filtering, and human approval for sensitive actions.

## Log threat hunting

Evaluated on synthetic logs from `logs/simulate.py` using RFC 5737 documentation IP ranges.

* 6 injected attacker behaviours (brute force, password spraying, brute-force-then-success,
  Nikto-style enumeration, sqlmap-style injection, low-volume stealth exploitation) vs. 10 benign hosts.
* All 6 are detected by the rule engine; the Isolation Forest independently flags 5 of 6
  (the brute-force-then-success host blends in volumetrically - the rules catch it).
* 0 false positives on the benign hosts, verified across several simulator seeds in the test suite.

**Caveat:** synthetic data is cleaner than production traffic. Expect to tune `Config` thresholds
(and benefit from the ML layer's population-relative scoring) when pointing this at real logs.
