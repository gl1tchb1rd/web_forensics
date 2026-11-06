from unittest.mock import patch
from django.test import SimpleTestCase
from forensics.headers import analyze_header, extract_ips

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

    def test_authentication_pass_is_not_claimed_verified(self):
        report = analyze_header("AZ", HEADER)
        auth = next(s for s in report["sections"] if s["title"] == "Authentifizierung laut Header")
        self.assertIn("nicht verifiziert", auth["rows"][0][0])
        self.assertIn("Keine eigenständige", auth["note"])

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
