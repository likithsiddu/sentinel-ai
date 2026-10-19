import unittest

from sentinelai.logs import Config, analyze, detect_format, parse_ssh, parse_web
from sentinelai.logs.anomaly import detect_anomalies
from sentinelai.logs.rules import run_rules, web_attack_hits
from sentinelai.logs.simulate import generate

SSH_FAIL = "Oct 19 10:22:01 bastion sshd[812]: Failed password for invalid user admin from 203.0.113.5 port 44122 ssh2"
SSH_OK = "Oct 19 10:22:09 bastion sshd[813]: Accepted publickey for alice from 10.0.0.12 port 50000 ssh2"
WEB = '203.0.113.9 - - [19/Oct/2026:10:22:01 +0000] "GET /a?id=1%20UNION%20SELECT%201 HTTP/1.1" 200 512 "-" "sqlmap/1.8"'


class ParserTests(unittest.TestCase):
    def test_ssh_parse(self):
        e = list(parse_ssh([SSH_FAIL, SSH_OK], 2026))
        self.assertEqual([x.action for x in e], ["failed", "accepted"])
        self.assertEqual(e[0].user, "admin")
        self.assertEqual(e[0].ip, "203.0.113.5")

    def test_web_parse(self):
        e = list(parse_web([WEB]))[0]
        self.assertEqual((e.status, e.method), (200, "GET"))
        self.assertIn("sqlmap", e.user_agent)

    def test_format_detection(self):
        self.assertEqual(detect_format([SSH_FAIL]), "ssh")
        self.assertEqual(detect_format([WEB]), "web")
        self.assertEqual(detect_format(["garbage"]), "unknown")

    def test_garbage_lines_ignored(self):
        self.assertEqual(list(parse_ssh(["nonsense", ""], 2026)), [])


class RuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ssh, web = generate(7)
        cls.events = list(parse_ssh(ssh, 2026)) + list(parse_web(web))
        cls.findings = run_rules(cls.events)

    def rules_for(self, ip):
        return {f.rule for f in self.findings if f.ip == ip}

    def test_brute_force(self):
        self.assertIn("SSH-BRUTE-FORCE", self.rules_for("203.0.113.45"))

    def test_spraying(self):
        r = self.rules_for("198.51.100.23")
        self.assertIn("SSH-PASSWORD-SPRAY", r)
        self.assertNotIn("SSH-BRUTE-FORCE", r)

    def test_success_after_bruteforce_is_critical(self):
        f = [x for x in self.findings if x.rule == "SSH-SUCCESS-AFTER-BRUTE"]
        self.assertEqual(len(f), 1)
        self.assertEqual((f[0].ip, f[0].severity, f[0].technique), ("192.0.2.77", "CRITICAL", "T1078"))

    def test_web_attacks(self):
        self.assertIn("WEB-SQL", self.rules_for("198.51.100.200"))
        r = self.rules_for("192.0.2.150")
        self.assertTrue({"WEB-PATH", "WEB-COMMAND"} <= r)

    def test_scanner_and_enumeration(self):
        r = self.rules_for("203.0.113.99")
        self.assertTrue({"WEB-SCANNER-UA", "WEB-FORCED-BROWSING", "WEB-SENSITIVE-PROBE"} <= r)

    def test_no_false_positives_on_benign_hosts(self):
        benign = {f"10.0.0.{i}" for i in range(11, 21)}
        self.assertFalse({f.ip for f in self.findings} & benign)

    def test_double_encoded_traversal(self):
        e = list(parse_web(['1.2.3.4 - - [19/Oct/2026:10:00:00 +0000] "GET /f?p=%252e%252e%252fetc%252fpasswd HTTP/1.1" 400 0']))[0]
        self.assertIn("Path traversal", web_attack_hits(e))

    def test_thresholds_configurable(self):
        strict = run_rules(self.events, Config(ssh_fail_threshold=500))
        self.assertNotIn("SSH-BRUTE-FORCE", {f.rule for f in strict})


class AnomalyTests(unittest.TestCase):
    def test_ml_flags_attackers_not_benign(self):
        ssh, web = generate(7)
        ev = list(parse_ssh(ssh, 2026)) + list(parse_web(web))
        findings, _ = detect_anomalies(ev)
        flagged = {f.ip for f in findings}
        self.assertTrue(flagged)
        self.assertFalse({ip for ip in flagged if ip.startswith("10.0.0.")})
        self.assertTrue({"203.0.113.45", "203.0.113.99"} <= flagged)

    def test_ml_skips_tiny_populations(self):
        ev = list(parse_ssh([SSH_FAIL, SSH_OK], 2026))
        findings, notes = detect_anomalies(ev)
        self.assertEqual(findings, [])
        self.assertIn("skipped", notes[0])

    def test_deterministic(self):
        ssh, web = generate(7)
        ev = list(parse_ssh(ssh, 2026)) + list(parse_web(web))
        a = sorted(f.ip for f in detect_anomalies(ev)[0])
        b = sorted(f.ip for f in detect_anomalies(ev)[0])
        self.assertEqual(a, b)

    def test_robust_across_seeds(self):
        for seed in (1, 2, 3):
            ssh, web = generate(seed)
            ev = list(parse_ssh(ssh, 2026)) + list(parse_web(web))
            findings, _ = analyze(ev)
            flagged = {f.ip for f in findings}
            self.assertTrue({"203.0.113.45", "198.51.100.23", "192.0.2.77", "203.0.113.99",
                             "198.51.100.200", "192.0.2.150"} <= flagged, f"seed {seed}")
            self.assertFalse({ip for ip in flagged if ip.startswith("10.0.0.")}, f"seed {seed}")


if __name__ == "__main__":
    unittest.main()
