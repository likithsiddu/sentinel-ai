"""Framework mappings used to label findings (MITRE ATT&CK, MITRE ATLAS, OWASP LLM Top 10)."""

ATTACK = {
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1110.003": ("Brute Force: Password Spraying", "Credential Access"),
    "T1078": ("Valid Accounts", "Initial Access / Persistence"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1595.002": ("Active Scanning: Vulnerability Scanning", "Reconnaissance"),
    "T1595.003": ("Active Scanning: Wordlist Scanning", "Reconnaissance"),
    "T1083": ("File and Directory Discovery", "Discovery"),
}

ATLAS = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0057": "LLM Data Leakage",
}

OWASP_LLM = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
}


def attack_label(tid: str | None) -> str:
    if not tid or tid not in ATTACK:
        return "-"
    name, tactic = ATTACK[tid]
    return f"{tid} {name} ({tactic})"
