import hashlib
import http.client
import socket
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from forensics.domain import analyze_domain, make_plan
from forensics.network import NetworkError, open_whois
from forensics.registration import registration_domain
from forensics.report import new_report
from forensics.whois import MAX_RESPONSE, add_whois, looks_like_domain, referrals, server_name, whois_bundle, whois_fields, whois_query


def reply(server, query, text, error=""):
    return {"server": server, "query": query, "text": text, "error": error, "ok": not error,
            "complete": not error, "sha256": hashlib.sha256(text.encode()).hexdigest(), "bytes": len(text.encode()),
            "captured_at": "2026-11-06T12:00:00+00:00", "encoding": "UTF-8", "referrals_found": [], "rejected": []}


class WhoisChainTests(SimpleTestCase):
    def run_chain(self, answers, **kwargs):
        calls = []
        def query(server, value):
            calls.append((server, value))
            answer = answers.get((server, value), answers.get(server))
            self.assertIsNotNone(answer, f"Unexpected WHOIS query: {server} / {value}")
            return reply(server, value, answer)
        with patch("forensics.whois.whois_query", side_effect=query):
            bundle = whois_bundle("example.com", **kwargs)
        return bundle, calls

    def test_chain_continues_after_registrar_and_follows_all_branches(self):
        answers = {
            "whois.iana.org": "whois: whois.registry.example\n",
            "whois.registry.example": "Registrar WHOIS Server: whois.registrar.example\nReferralServer: whois://second.registrar.example:43/\n",
            "whois.registrar.example": "  WHOIS  Server: whois.final.example\n",
            "second.registrar.example": "Domain Name: EXAMPLE.COM\n",
            "whois.final.example": "Domain Name: EXAMPLE.COM\nRegistrar: Final company\n",
        }
        bundle, calls = self.run_chain(answers)
        self.assertTrue(bundle["complete"])
        self.assertEqual(len(calls), 5)
        self.assertEqual(bundle["queried_servers"][-1], "whois.final.example")
        self.assertEqual(bundle["attempts"][-1]["referred_by"], "whois.registrar.example")

    def test_iana_full_domain_then_tld_fallback(self):
        bundle, calls = self.run_chain({("whois.iana.org", "example.com"): "No match\n", ("whois.iana.org", "com"): "refer: whois.registry.example\n", "whois.registry.example": "Domain Name: EXAMPLE.COM\n"})
        self.assertTrue(bundle["complete"])
        self.assertEqual(calls[:2], [("whois.iana.org", "example.com"), ("whois.iana.org", "com")])

    def test_verisign_query_variants_and_earlier_referrals_are_retained(self):
        bundle, calls = self.run_chain({
            "whois.iana.org": "whois: whois.verisign-grs.com\n",
            ("whois.verisign-grs.com", "dom example.com"): "Whois Server: whois.registrar.example\n",
            ("whois.verisign-grs.com", "domain example.com"): "Syntax error\n",
            ("whois.verisign-grs.com", "=example.com"): "Domain Name: EXAMPLE.COM\n",
            "whois.registrar.example": "Domain Name: EXAMPLE.COM\n",
        })
        self.assertTrue(bundle["complete"])
        self.assertEqual([query for server, query in calls if server == "whois.verisign-grs.com"], ["dom example.com", "domain example.com", "=example.com"])
        self.assertEqual(bundle["attempts"][-1]["server"], "whois.registrar.example")

    def test_verisign_last_variant_uses_plain_domain(self):
        answers = {"whois.iana.org": "whois: whois.crsnic.net\n", "whois.crsnic.net": "No match\n"}
        bundle, calls = self.run_chain(answers)
        self.assertEqual([query for server, query in calls if server == "whois.crsnic.net"], ["dom example.com", "domain example.com", "=example.com", "example.com"])
        self.assertEqual(len(bundle["attempts"]), 5)

    def test_self_references_and_cycles_do_not_requery_servers(self):
        bundle, calls = self.run_chain({"whois.iana.org": "refer: whois.a.example\n", "whois.a.example": "Registrar Whois Server: whois.b.example\nwhois: whois.a.example\n", "whois.b.example": "whois: whois.a.example\n"})
        self.assertEqual(len(calls), 3)
        self.assertTrue(bundle["complete"])
        self.assertTrue(bundle["skipped"])

    def test_limit_is_an_explicit_incomplete_result(self):
        bundle, calls = self.run_chain({"whois.iana.org": "refer: whois.a.example\n", "whois.a.example": "whois: whois.b.example\n"}, max_referral_servers=1)
        self.assertFalse(bundle["complete"])
        self.assertTrue(bundle["referral_limit_reached"])
        self.assertEqual(bundle["pending"], ["whois.b.example"])

    def test_protocol_mismatch_is_not_silently_downgraded(self):
        bundle, calls = self.run_chain({"whois.iana.org": "whois: whois.registry.example\n", "whois.registry.example": "ReferralServer: rwhois://rwhois.provider.example:4321\n"})
        self.assertEqual(len(calls), 2)
        self.assertFalse(bundle["complete"])
        self.assertIn("RWHOIS", bundle["attempts"][-1]["rejected"][0])

    def test_failed_verisign_transport_does_not_retry_query_syntax(self):
        def query(server, value):
            return reply(server, value, "whois: whois.verisign-grs.com\n" if server == "whois.iana.org" else "", "" if server == "whois.iana.org" else "Connection failed")
        with patch("forensics.whois.whois_query", side_effect=query) as queried:
            bundle = whois_bundle("example.com")
        self.assertEqual(queried.call_count, 2)
        self.assertFalse(bundle["complete"])

    def test_whois_rate_limit_is_not_called_a_successful_terminal(self):
        def query(server, value):
            return reply(server, value, "whois: whois.verisign-grs.com\n" if server == "whois.iana.org" else "WHOIS LIMIT EXCEEDED\n")
        with patch("forensics.whois.whois_query", side_effect=query) as queried:
            bundle = whois_bundle("example.com")
        self.assertFalse(bundle["complete"])
        self.assertEqual(queried.call_count, 2)
        self.assertIn("Abfragelimit", bundle["attempts"][-1]["error"])

    def test_unstructured_help_reply_is_not_a_verified_end(self):
        bundle, _ = self.run_chain({"whois.iana.org": "whois: whois.registry.example\n", "whois.registry.example": "Welcome. Please use RDAP for this service.\n"})
        self.assertFalse(bundle["complete"])
        self.assertIn("Kettenende ist nicht bestätigt", bundle["reason"])

    def test_denic_is_a_legitimate_terminal_for_de(self):
        def query(server, value):
            return reply(server, value, "whois: whois.denic.de\n" if server == "whois.iana.org" else "Domain: example.de\nStatus: connect\n")
        with patch("forensics.whois.whois_query", side_effect=query):
            bundle = whois_bundle("example.de")
        self.assertTrue(bundle["complete"])
        self.assertIn("regulär bei DENIC", bundle["reason"])

    def test_report_preserves_stages_queries_and_raw_answers(self):
        report = new_report("domain", "AZ", "example.com", "example.com")
        with patch("forensics.whois.whois_query", side_effect=lambda server, query: reply(server, query, "whois: whois.registry.example\n" if server == "whois.iana.org" else "Domain Name: EXAMPLE.COM\n")):
            bundle = add_whois(report, "example.com")
        self.assertEqual(len(report["sections"]), 3)
        self.assertEqual(report["sections"][1]["raw"], bundle["attempts"][0]["text"])
        self.assertIn(["Abfrage", "example.com"], report["sections"][2]["rows"])
        self.assertIn("whois://whois.registry.example:43", report["sources"])


class WhoisProtocolTests(SimpleTestCase):
    def test_unicode_domain_reply_is_recognized(self):
        self.assertTrue(looks_like_domain("  Domain Name: BÜCHER.DE\n", "xn--bcher-kva.de"))
        self.assertFalse(looks_like_domain("Domain Name: different.example\nexample.com is a query\n", "example.com"))

    def test_registrar_dates_and_nameservers_are_source_attributed(self):
        rows = whois_fields("Registrar: Example registrar\nCreation Date: 2000-01-02\nName Server: ns.example\nDescription: Legal notice\n")
        self.assertIn(["Registrar (laut WHOIS)", "Example registrar"], rows)
        self.assertIn(["Registrierungsdatum (laut WHOIS)", "2000-01-02"], rows)
        self.assertEqual(len(rows), 3)

    def test_registrant_privacy_and_contact_data_are_not_hidden_from_report(self):
        text = "Domain Name: EXAMPLE.COM\nRegistrant Name: REDACTED FOR PRIVACY\nRegistrant Organization: Example association\nRegistrant Street: Musterweg 1\nRegistrant Email: contact@example.com\nTech Name: Example administrator\nRegistrar Abuse Contact Email: abuse@example.org\n"
        rows = whois_fields(text)
        self.assertIn(["Domaininhaber / Name (laut WHOIS)", "REDACTED FOR PRIVACY"], rows)
        self.assertIn(["Domaininhaber / Organisation (laut WHOIS)", "Example association"], rows)
        self.assertIn(["Domaininhaber / E-Mail (laut WHOIS)", "contact@example.com"], rows)
        self.assertIn(["Technischer Kontakt / Name (laut WHOIS)", "Example administrator"], rows)
        self.assertIn(["Registrar / Missbrauchskontakt / E-Mail (laut WHOIS)", "abuse@example.org"], rows)

    def test_long_nameserver_list_does_not_discard_later_holder_name(self):
        text = "\n".join(f"Name Server: ns{index}.example.org" for index in range(120)) + "\nRegistrant Name: REDACTED FOR PRIVACY\n"
        rows = whois_fields(text)
        self.assertIn(["Domaininhaber / Name (laut WHOIS)", "REDACTED FOR PRIVACY"], rows)
        self.assertEqual(len(rows), 96)

    def test_socket_chain_carries_registrant_value_into_report(self):
        report = new_report("domain", "TEST", "example.com", "example.com")
        replies = {"whois.iana.org": b"whois: whois.registry.example\r\n",
                   "whois.registry.example": b"Domain Name: EXAMPLE.COM\r\nRegistrar WHOIS Server: whois.registrar.example\r\n",
                   "whois.registrar.example": b"Domain Name: EXAMPLE.COM\r\nRegistrant Name: REDACTED FOR PRIVACY\r\n"}
        sockets = []
        def open_socket(host):
            sock = MagicMock()
            sock.recv.side_effect = [replies[host], b""]
            connection = MagicMock()
            connection.__enter__.return_value = sock
            sockets.append(sock)
            return connection
        with patch("forensics.whois.open_whois", side_effect=open_socket):
            add_whois(report, "example.com")
        self.assertEqual(len(sockets), 3)
        self.assertIn(["Domaininhaber / Name (laut WHOIS)", "REDACTED FOR PRIVACY"], report["sections"][-1]["rows"])
        self.assertIn("Registrant Name: REDACTED FOR PRIVACY", report["sections"][-1]["raw"])
        self.assertTrue(any("whois.registrar.example: REDACTED FOR PRIVACY" in item["text"] for item in report["summary"]))

    def test_referral_label_variants_whitespace_and_duplicates(self):
        text = "\n".join(["  REFER: WHOIS.A.EXAMPLE.", " Whois\tServer : whois.a.example", "Registrar WHOIS Server: whois.b.example", "Registry WHOIS Server: whois.c.example", " Referral Server: whois://whois.d.example:43/ (comment)", "ReferralServer: <whois.e.example> (comment)", "whois: whois.f.example, (comment)", "Description: whois: unrelated.example"])
        hosts, errors = referrals(text)
        self.assertEqual(hosts, [f"whois.{letter}.example" for letter in "abcdef"])
        self.assertEqual(errors, [])

    def test_bad_referrals_rejected(self):
        for value in ("<>", "127.0.0.1", "whois://10.0.0.1", "whois://whois.example:22", "https://whois.example/path", "whois://user:pass@whois.example", "metadata.internal", "whois://whois.example/path"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                server_name(value)

    def test_query_is_single_crlf_terminated_command(self):
        sock = MagicMock()
        sock.recv.side_effect = [b"Domain Name: EXAMPLE.COM\r\n", b""]
        with patch("forensics.whois.open_whois") as opened:
            opened.return_value.__enter__.return_value = sock
            result = whois_query("whois.example", "dom example.com")
        sock.sendall.assert_called_once_with(b"dom example.com\r\n")
        self.assertTrue(result["complete"])
        self.assertEqual(result["sha256"], hashlib.sha256(b"Domain Name: EXAMPLE.COM\r\n").hexdigest())

    def test_timeout_preserves_partial_reply_and_marks_incomplete(self):
        sock = MagicMock()
        sock.recv.side_effect = [b"Registrar WHOIS Server: whois.next.example\r\n", socket.timeout()]
        with patch("forensics.whois.open_whois") as opened:
            opened.return_value.__enter__.return_value = sock
            result = whois_query("whois.example", "example.com")
        self.assertFalse(result["complete"])
        self.assertIn("Teilantwort", result["error"])
        self.assertTrue(result["text"])

    def test_response_size_is_bounded_and_preserved(self):
        sock = MagicMock()
        sock.recv.side_effect = lambda count: b"x" * count
        with patch("forensics.whois.open_whois") as opened:
            opened.return_value.__enter__.return_value = sock
            result = whois_query("whois.example", "example.com")
        self.assertEqual(result["bytes"], MAX_RESPONSE + 1)
        self.assertFalse(result["complete"])
        self.assertIn("größenlimit", result["error"].lower())

    def test_command_injection_is_blocked_before_connect(self):
        with patch("forensics.whois.open_whois") as opened:
            result = whois_query("whois.example", "example.com\r\nsecond-command")
        opened.assert_not_called()
        self.assertFalse(result["ok"])

    def test_private_dns_target_is_blocked_before_connect(self):
        with patch("forensics.network.resolve_public", side_effect=NetworkError("private target")), patch("forensics.network._socket") as dial:
            with self.assertRaises(NetworkError):
                open_whois("whois.example")
        dial.assert_not_called()

    def test_proxy_tunnel_uses_pinned_public_ip_and_port_43(self):
        with patch("forensics.network.resolve_public", return_value=["1.1.1.1"]), patch("forensics.network._socket") as dial:
            open_whois("whois.example")
        self.assertEqual(dial.call_args.args[:2], ("whois.example", "1.1.1.1"))
        self.assertEqual(dial.call_args.kwargs["port"], 43)

    def test_unreachable_first_address_does_not_prevent_second_public_address(self):
        sock = MagicMock()
        with patch("forensics.network.resolve_public", return_value=["1.1.1.1", "8.8.8.8"]), patch("forensics.network._socket", side_effect=[OSError("unreachable"), sock]) as dial:
            self.assertIs(open_whois("whois.example"), sock)
        self.assertEqual([call.args[1] for call in dial.call_args_list], ["1.1.1.1", "8.8.8.8"])
        self.assertTrue(all(call.kwargs["port"] == 43 for call in dial.call_args_list))

    def test_proxy_rejection_does_not_trigger_direct_connection_fallback(self):
        with patch("forensics.network.resolve_public", return_value=["1.1.1.1", "8.8.8.8"]), patch("forensics.network._socket", side_effect=http.client.HTTPException("CONNECT denied")) as dial:
            with self.assertRaisesRegex(NetworkError, "HTTP CONNECT zu TCP 43"):
                open_whois("whois.example")
        dial.assert_called_once()


class RegistrationDomainTests(SimpleTestCase):
    def test_public_suffix_snapshot_is_used_offline(self):
        with patch("requests.sessions.Session.get", side_effect=AssertionError("No PSL download")):
            for value, expected in (("www.example.co.uk", "example.co.uk"), ("mail.sub.example.com", "example.com"), ("www.bücher.de", "xn--bcher-kva.de"), ("project.github.io", "github.io")):
                self.assertEqual(registration_domain(value)[0], expected)

    def test_public_suffix_alone_is_rejected(self):
        with self.assertRaises(ValueError):
            registration_domain("co.uk")

    def test_dns_only_analysis_does_not_require_a_registrable_domain(self):
        plan = make_plan("domain", "co.uk", {})
        self.assertEqual(plan["domain"], "co.uk")

    def test_plan_discloses_whois_without_querying_it(self):
        with patch("forensics.whois.open_whois") as opened:
            plan = make_plan("domain", "www.example.com", {"whois": True})
        opened.assert_not_called()
        self.assertEqual(plan["registration_domain"], "example.com")
        self.assertTrue(any("whois.iana.org" in recipient[1] and "TCP 43" in recipient[0] for recipient in plan["recipients"]))

    def test_registration_uses_base_domain_but_dns_keeps_input(self):
        def dns_answer(domain, kind):
            self.assertEqual(domain, "www.example.com")
            return {"kind": kind, "values": [], "status": "empty", "ttl": 0, "note": ""}
        plan = {"options": {"whois": True}, "recipients": [], "errors": []}
        with patch("forensics.domain.dns_record", side_effect=dns_answer), patch("forensics.domain.add_whois") as whois:
            report = analyze_domain("AZ", "www.example.com", plan)
        self.assertEqual(whois.call_args.args[1], "example.com")
        self.assertTrue(any("Subdomain" in item["text"] for item in report["summary"]))
