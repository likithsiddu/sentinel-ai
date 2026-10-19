"""Heuristic detection layer: text normalisation + weighted attack-pattern library."""
from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass

ZERO_WIDTH = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")
UNICODE_TAGS = re.compile("[\U000e0000-\U000e007f]")       # "ASCII smuggling" invisible payloads
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")


@dataclass(frozen=True)
class Rule:
    name: str
    category: str
    weight: float
    regex: re.Pattern
    owasp: str
    atlas: str
    why: str


def _r(name, cat, w, rx, owasp, atlas, why):
    return Rule(name, cat, w, re.compile(rx, re.I), owasp, atlas, why)


RULES = [
    _r("instruction_override", "Instruction override", 0.85,
       r"\b(ignore|disregard|forget|override|bypass|discard)\b[^.\n]{0,40}"
       r"\b(previous|prior|above|earlier|preceding|all|any|your|the)\b[^.\n]{0,40}"
       r"\b(instructions?|prompts?|rules|guidelines|directions|context|constraints)\b",
       "LLM01", "AML.T0051", "Tries to cancel the developer's instructions."),
    _r("prompt_extraction", "System prompt extraction", 0.80,
       r"\b(reveal|show|print|repeat|output|display|leak|dump|recite|tell me)\b[^.\n]{0,50}"
       r"\b(system (prompt|message|instructions?)|initial prompt|hidden (instructions?|prompt)|"
       r"(your|the) (original|full|exact) (instructions?|prompt)|everything above)\b",
       "LLM07", "AML.T0057", "Attempts to leak confidential system prompt."),
    _r("jailbreak_persona", "Jailbreak / persona", 0.70,
       r"(\bdan\b|do anything now|developer mode|jailbr[eo]ak(ed)?|\b(no|without)( any)? "
       r"(restrictions?|filters?|limitations?|rules|censorship|guardrails|ethics)\b|"
       r"\bunrestricted (ai|mode|model)\b)",
       "LLM01", "AML.T0054", "Known jailbreak persona / policy-removal language."),
    _r("role_reassignment", "Role reassignment", 0.50,
       r"\b(you are (now|no longer)|from now on,? you|act as (if you (have|are)|an? (unfiltered|evil|"
       r"uncensored))|pretend (that )?you (are|have) (no|an? (evil|unrestricted|unfiltered)))\b",
       "LLM01", "AML.T0054", "Attempts to rewrite the model's identity."),
    _r("fake_delimiters", "Context / delimiter smuggling", 0.65,
       r"(</?(system|assistant|instructions?|prompt)>|\[/?(inst|system)\]|<\|(im_start|im_end|system)\|>|"
       r"(^|\s)#{2,}\s*(system|instructions?)\b|(^|[.!?]\s)(system|assistant)\s*:)",
       "LLM01", "AML.T0051", "Forges chat-template or role delimiters."),
    _r("markdown_exfil", "Data exfiltration", 0.80,
       r"!\[[^\]]*\]\(https?://[^)\s]*(\?|&)[^)\s]*(=|\{|%7b)",
       "LLM05", "AML.T0057", "Markdown image with query params can leak data via auto-fetch."),
    _r("send_to_url", "Data exfiltration", 0.60,
       r"\b(send|post|upload|exfiltrate|forward|transmit)\b[^.\n]{0,70}\b(to|at|via)\b[^.\n]{0,30}https?://",
       "LLM02", "AML.T0057", "Instructs the model to ship data to an external URL."),
    _r("secret_request", "Secret disclosure", 0.60,
       r"\b(reveal|print|show|give me|tell me|dump|leak|list)\b[^.\n]{0,30}"
       r"\b(api[_ -]?keys?|passwords?|secrets?|access tokens?|credentials|environment variables|env vars)\b",
       "LLM02", "AML.T0057", "Requests secrets or credentials."),
    _r("dangerous_command", "Tool / command abuse", 0.55,
       r"(\brm\s+-rf\b|\bdrop\s+table\b|curl[^|\n]*\|\s*(ba)?sh|chmod\s+777|/etc/(passwd|shadow)|"
       r"\bos\.system\(|\bsubprocess\.|\beval\()",
       "LLM06", "AML.T0051", "Embeds destructive or execution payloads for tool-using agents."),
    _r("tool_hijack", "Tool / command abuse", 0.35,
       r"\b(call|invoke|execute|run|use)\b[^.\n]{0,30}\b(the )?(function|tool|command|shell|terminal)\b[^.\n]{0,40}"
       r"\b(without|silently|immediately|secretly)\b",
       "LLM06", "AML.T0051", "Pushes an agent to act without oversight."),
    _r("indirect_injection", "Indirect injection", 0.80,
       r"(\b(important|new|urgent)\s+(instructions?|message|notice)\s+(for|to)\s+(the\s+)?(ai|assistant|model|llm|chatbot)\b|"
       r"\b(if|when)\s+you\s+(are|'re)\s+(an?\s+)?(ai|llm|assistant|language model)\b[^.\n]{0,60}\b(summari[sz]|read|process)|"
       r"\bai\s+(assistant|agents?)\s*[:,]\s*(please\s+)?(ignore|do|send|forward|visit))",
       "LLM01", "AML.T0051", "Hidden instructions aimed at an AI reading third-party content."),
]


def normalize(text: str) -> tuple[str, list[str]]:
    """Canonicalise text so trivial obfuscation does not defeat detection.
    Returns (normalised_text, obfuscation_signals)."""
    signals = []
    if UNICODE_TAGS.search(text):
        signals.append("unicode_tag_smuggling")
        text = UNICODE_TAGS.sub("", text)
    if ZERO_WIDTH.search(text):
        signals.append("zero_width_chars")
        text = ZERO_WIDTH.sub("", text)
    folded = unicodedata.normalize("NFKC", text)
    if folded != text:
        signals.append("unicode_homoglyphs_or_fullwidth")
    return re.sub(r"\s+", " ", folded).strip().lower(), signals


def decode_base64_blobs(text: str) -> list[str]:
    out = []
    for blob in B64.findall(text):
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8")
        except Exception:
            continue
        if raw and sum(c.isprintable() or c.isspace() for c in raw) / len(raw) > 0.95:
            out.append(raw)
    return out


def match_rules(text: str) -> list[Rule]:
    """Match against both the plain and leetspeak-folded text (1gn0re -> ignore)."""
    variants = {text, text.translate(LEET)}
    hit = {}
    for v in variants:
        for rule in RULES:
            if rule.regex.search(v):
                hit[rule.name] = rule
    return list(hit.values())
