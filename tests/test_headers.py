from unittest.mock import patch
from django.test import SimpleTestCase
from forensics.headers import analyze_header, extract_ips
from forensics.mailauth import authentication_results
from forensics.mailroute import address_type
from email import policy
from email.parser import HeaderParser

HEADER = """Received: from relay.example [198.51.100.2] by inbox.example; Fri, 06 Nov 2026 12:01:00 +0000
Received: from sender.example [203.0.113.8] by relay.example; Fri, 06 Nov 2026 12:00:00 +0000
Authentication-Results: inbox.example; spf=pass; dkim=pass; dmarc=pass
From: Absender <post@sender.example>
Reply-To: help@other.example
To: empfang@inbox.example
Date: Fri, 06 Nov 2026 11:59:00 +0000
Subject: Prüfung <b>untrusted</b> & ÄÖÜ
Message-ID: <demo@sender.example>
"""


class HeaderTests(SimpleTestCase):
    def test_offline_path_never_uses_network(self):
        with patch("socket.socket", side_effect=AssertionError("No networking allowed")), patch("forensics.domain.add_networks") as networks:
            report = analyze_header("AZ 123/26", HEADER)
        networks.assert_not_called()
        self.assertIn("Keine externen Abfragen durchgeführt.", report["sources"])
        self.assertEqual(report["sections"][-1]["raw"], HEADER)
        self.assertEqual(report["case"], "AZ 123/26")

    def test_chronological_received_and_delta(self):
        report = analyze_header("AZ", HEADER)
        route = next(s for s in report["sections"] if s["title"] == "Transportweg laut Received")
        self.assertIn("sender.example", route["rows"][0][1])
        self.assertIn("60 Sekunden", route["rows"][1][1])

    def test_negative_time_is_reported(self):
        report = analyze_header("AZ", HEADER.replace("12:01:00", "11:58:00"))
        self.assertTrue(any("Zeitwiderspruch" in item["text"] for item in report["summary"]))

    def test_authentication_pass_is_explained_as_recorded_server_result(self):
        report = analyze_header("AZ", HEADER)
        auth = next(s for s in report["sections"] if s["title"] == "Authentifizierung laut Header")
        self.assertEqual(auth["rows"][0][0], "SPF — Bestanden (pass)")
        self.assertIn("zum Versand zugelassen", auth["rows"][0][1])
        self.assertIn("inbox.example", auth["rows"][0][1])
        self.assertTrue(any("Anmelde- und Serverprotokollen" in text for text in report["limitations"]))

    def test_rejects_body_instead_of_silently_ignoring(self):
        with self.assertRaisesRegex(ValueError, "Nachrichtentext"):
            analyze_header("AZ", HEADER + "\nPrivate message body")

    def test_limits_and_invalid_inputs(self):
        for text in ("", "not a header", "Subject: " + "x" * 65536, "Subject: a\x00b"):
            with self.subTest(text=text[:20]), self.assertRaises(ValueError):
                analyze_header("AZ", text)

    def test_duplicate_fields_and_missing_values(self):
        report = analyze_header("AZ", "From: a@one.example\nFrom: b@two.example\n")
        self.assertTrue(any("mehrfach" in item["text"] for item in report["summary"]))
        self.assertTrue(any("Message-ID fehlt" in item["text"] for item in report["summary"]))

    def test_ipv4_ipv6_candidates_are_validated(self):
        self.assertEqual(extract_ips(["from [IPv6:2606:4700::1111] and [192.0.2.1]; 999.999.999.999"]), ["2606:4700::1111", "192.0.2.1"])

    def auth_section(self, header):
        report = analyze_header("AZ", header)
        return report, next(s for s in report["sections"] if s["title"] == "Authentifizierung laut Header")

    def test_spf_pass_for_other_domain_is_distinguished_from_dmarc_failure(self):
        report, auth = self.auth_section("From: sender@visible.example\nAuthentication-Results: mx.recipient.example; spf=pass smtp.mailfrom=bounce@other.example; dkim=pass header.d=other.example; dmarc=fail header.from=visible.example\n")
        self.assertIn("other.example", auth["rows"][0][1])
        self.assertIn("visible.example", auth["rows"][2][1])
        self.assertIn("DMARC — Nicht bestanden (fail)", [row[0] for row in auth["rows"]])
        self.assertTrue(any("DMARC: Nicht bestanden" in item["text"] for item in report["summary"]))
        self.assertIn("Spoofing", auth["rows"][-1][1])

    def test_forwarded_message_can_pass_dmarc_despite_spf_failure(self):
        _, auth = self.auth_section("From: sender@sender.example\nAuthentication-Results: inbox.example; spf=fail smtp.mailfrom=sender.example; dkim=pass header.d=sender.example; dmarc=pass header.from=sender.example\n")
        inference = auth["rows"][-1][1]
        self.assertIn("passende DKIM-Signatur", inference)
        self.assertIn("Weiterleitung", inference)
        self.assertNotIn("Absenderfälschung", inference)

    def test_different_evaluators_are_not_merged_into_a_pass(self):
        report, auth = self.auth_section("From: sender@sender.example\nAuthentication-Results: inbox.example; spf=fail smtp.mailfrom=sender.example; dmarc=fail header.from=sender.example\nAuthentication-Results: relay.example; spf=pass smtp.mailfrom=sender.example; dmarc=pass header.from=sender.example\n")
        self.assertTrue(any("SPF: Unterschiedliche Ergebnisse" in item["text"] for item in report["summary"]))
        self.assertTrue(any("DMARC: Unterschiedliche Ergebnisse" in item["text"] for item in report["summary"]))
        self.assertIn("inbox.example", str(auth["rows"]))
        self.assertIn("relay.example", str(auth["rows"]))
        self.assertIn("nicht zu einer einheitlichen Bestätigung", auth["rows"][-1][1])

    def test_missing_none_and_errors_are_different_results(self):
        _, missing = self.auth_section("From: a@sender.example\n")
        self.assertEqual(missing["status"], "unavailable")
        self.assertIn("fehlendes Prüfergebnis ist kein Beleg", missing["rows"][-1][1])
        for method, result, phrase in (("spf", "none", "weder bestätigt noch verneint"), ("dmarc", "none", "keine fehlgeschlagene"), ("spf", "temperror", "vorübergehenden"), ("dkim", "permerror", "Konfigurationsfehlers"), ("spf", "softfail", "wahrscheinlich nicht zugelassen")):
            with self.subTest(method=method, result=result):
                _, auth = self.auth_section(f"From: a@sender.example\nAuthentication-Results: inbox.example; {method}={result}\n")
                row = next(row for row in auth["rows"] if row[0].startswith(method.upper()))
                self.assertIn(phrase, row[1])

    def test_comments_and_quoted_reasons_do_not_inject_results(self):
        value = 'Authentication-Results: inbox.example; spf=fail (spf=pass; dkim=pass) reason="spf=pass; dkim=pass"; dmarc=fail reason="text; spf=pass"\n'
        msg = HeaderParser(policy=policy.default).parsestr(value + "\n")
        self.assertEqual([(r["method"], r["result"]) for r in authentication_results(msg)], [("spf", "fail"), ("dmarc", "fail")])

    def test_received_spf_includes_domain_and_connection_ip(self):
        report, auth = self.auth_section("From: a@sender.example\nReceived-SPF: pass (sender is permitted) client-ip=8.8.4.4; envelope-from=sender@sender.example; receiver=inbox.example\n")
        self.assertIn("sender@sender.example", auth["rows"][0][1])
        self.assertIn("8.8.4.4", auth["rows"][0][1])
        ips = next(s for s in report["sections"] if s["title"] == "Erfasste IP-Adressen und ihre Rolle")
        self.assertEqual(ips["rows"][0][0], "8.8.4.4")
        self.assertIn("Received-SPF #1", ips["rows"][0][1])

    def test_arc_and_signature_presence_are_not_current_authentication_success(self):
        report, auth = self.auth_section("From: a@sender.example\nARC-Authentication-Results: i=1; old.example; spf=pass; dmarc=pass\nDKIM-Signature: v=1; d=sender.example; s=key; a=rsa-sha256; b=abc\n")
        self.assertEqual(auth["status"], "unavailable")
        self.assertFalse(any("Bestanden" in item["text"] for item in report["summary"]))
        technical = next(s for s in report["sections"] if s["title"] == "Signaturen und weitergereichte Prüfergebnisse")
        self.assertIn("old.example", str(technical["rows"]))
        self.assertIn("Signaturdomain: sender.example", str(technical["rows"]))

    def test_dmarc_for_different_from_domain_is_not_summarized_as_visible_domain_pass(self):
        report, auth = self.auth_section("From: a@visible.example\nAuthentication-Results: inbox.example; dmarc=pass header.from=other.example\n")
        self.assertTrue(any(row[0] == "Abweichende Domainangaben" for row in auth["rows"]))
        self.assertFalse(any("DMARC: Bestanden" in item["text"] for item in report["summary"]))
        self.assertTrue(any("visible.example" in item["text"] and "other.example" in item["text"] for item in report["summary"]))

    def test_ip_roles_follow_from_by_and_authenticated_submission(self):
        header = """Received: from mail.sender.example (mail.sender.example [8.8.8.8]) by inbox.recipient.example [1.1.1.1] with ESMTPS; Fri, 06 Nov 2026 12:01:00 +0000
Received: from workstation [192.168.1.5] by mail.sender.example [8.8.8.8] with ESMTPSA; Fri, 06 Nov 2026 12:00:00 +0000
X-Originating-IP: [9.9.9.9]
From: a@sender.example
"""
        report = analyze_header("AZ", header)
        ips = next(s for s in report["sections"] if s["title"] == "Erfasste IP-Adressen und ihre Rolle")
        rows = dict(ips["rows"])
        self.assertIn("Absender-Endpunkt", rows["192.168.1.5"])
        self.assertIn("Private interne", rows["192.168.1.5"])
        self.assertIn("Received-Station 1, from workstation", rows["192.168.1.5"])
        self.assertIn("Einlieferndes System", rows["8.8.8.8"])
        self.assertIn("Received-Station 2, from mail.sender.example", rows["8.8.8.8"])
        self.assertIn("Empfangsserver", rows["1.1.1.1"])
        self.assertIn("X-Originating-IP #1", rows["9.9.9.9"])
        self.assertEqual(len(rows), 4)

    def test_received_comments_cannot_change_transport_clause_roles(self):
        report = analyze_header("AZ", "Received: from mail.example (by unrelated.example [8.8.8.8]) by inbox.example [1.1.1.1]; Fri, 06 Nov 2026 12:00:00 +0000\n")
        ips = dict(next(s for s in report["sections"] if s["title"] == "Erfasste IP-Adressen und ihre Rolle")["rows"])
        self.assertIn("from mail.example", ips["8.8.8.8"])
        self.assertIn("by inbox.example", ips["1.1.1.1"])

    def test_unassigned_ip_is_not_labelled_as_sender_endpoint(self):
        report = analyze_header("AZ", "Received: by inbox.example id unknown [8.8.8.8]; Fri, 06 Nov 2026 12:00:00 +0000\n")
        ips = next(s for s in report["sections"] if s["title"] == "Erfasste IP-Adressen und ihre Rolle")
        self.assertIn("ohne eindeutig erkennbare Transportrolle", ips["rows"][0][1])

    def test_ip_address_categories_do_not_treat_special_ranges_as_public_endpoints(self):
        for ip, label in (("192.0.2.1", "Dokumentationsadresse"), ("2001:db8::1", "Dokumentationsadresse"), ("127.0.0.1", "Loopback"), ("169.254.1.1", "Link-lokale"), ("100.64.1.1", "Provider-NAT"), ("fc00::1", "Private interne"), ("224.0.0.1", "Multicast"), ("2606:4700::1111", "Öffentlich routbare IPv6")):
            with self.subTest(ip=ip):
                self.assertIn(label, address_type(ip))
