import json
from unittest.mock import patch
from django.test import SimpleTestCase
from forensics.rdap_chain import walk_domain_rdap
from forensics.report import new_report
from forensics.domain import add_rdap_section

REGISTRY = "https://registry.example/rdap/domain/example.com"
REGISTRAR = "https://registrar.example/v1/domain/EXAMPLE.COM"
FINAL = "https://final.example/domain/example.com"


def document(link=None, domain="example.com"):
    value = {"ldhName": domain, "objectClassName": "domain", "handle": "DOMAIN-123"}
    if link:
        value["links"] = [{"rel": "related", "type": "application/rdap+json", "href": link}]
    return json.dumps(value).encode()


class RdapChainTests(SimpleTestCase):
    def run_chain(self, replies, **kwargs):
        calls = []
        def fetch(url, **options):
            calls.append(url)
            return replies[url]
        result = walk_domain_rdap(REGISTRY, "example.com", ["registry.example"], fetch, **kwargs)
        return result, calls

    def test_related_links_continue_from_registry_to_registrar_and_beyond(self):
        result, calls = self.run_chain({REGISTRY: (200, {}, document(REGISTRAR)), REGISTRAR: (200, {}, document(FINAL)), FINAL: (200, {}, document())})
        self.assertTrue(result["complete"])
        self.assertEqual(calls, [REGISTRY, REGISTRAR, FINAL])
        self.assertEqual(result["steps"][-1]["parent"], REGISTRAR)

    def test_failed_registrar_does_not_discard_registry_answer(self):
        result, calls = self.run_chain({REGISTRY: (200, {}, document(REGISTRAR)), REGISTRAR: (503, {}, b"not available")})
        self.assertFalse(result["complete"])
        self.assertEqual(result["steps"][0]["data"]["handle"], "DOMAIN-123")
        self.assertIn("503", result["reason"])

    def test_redirects_are_recorded_separately(self):
        result, calls = self.run_chain({REGISTRY: (301, {"Location": REGISTRAR}, b"redirect"), REGISTRAR: (200, {}, document())})
        self.assertEqual(len(result["steps"]), 2)
        self.assertEqual(result["steps"][0]["status"], 301)
        self.assertTrue(result["complete"])

    def test_cycles_are_deduplicated(self):
        result, calls = self.run_chain({REGISTRY: (200, {}, document(REGISTRAR)), REGISTRAR: (200, {}, document(REGISTRY))})
        self.assertEqual(calls, [REGISTRY, REGISTRAR])
        self.assertTrue(result["complete"])
        self.assertEqual(result["skipped"], [REGISTRY])

    def test_unrelated_domain_private_and_non_https_targets_are_not_requested(self):
        for target in ("https://127.0.0.1/domain/example.com", "https://metadata.internal/domain/example.com", "https://evil.example/domain/other.com", "http://registrar.example/domain/example.com", "https://registrar.example:22/domain/example.com", "https://registrar.example/entity/contact", "https://registrar.example/domain/example.com?contact=private"):
            with self.subTest(target=target):
                result, calls = self.run_chain({REGISTRY: (200, {}, document(target))})
                self.assertEqual(calls, [REGISTRY])
                self.assertFalse(result["complete"])

    def test_request_limit_is_not_called_a_terminal_result(self):
        result, calls = self.run_chain({REGISTRY: (200, {}, document(REGISTRAR))}, max_requests=1)
        self.assertFalse(result["complete"])
        self.assertEqual(result["pending"], [REGISTRAR])

    def test_mismatched_domain_in_response_is_rejected(self):
        result, calls = self.run_chain({REGISTRY: (200, {}, document(REGISTRAR, domain="other.com"))})
        self.assertFalse(result["complete"])
        self.assertEqual(calls, [REGISTRY])
        self.assertIsNone(result["steps"][0]["data"])

    def test_report_includes_registry_and_failed_referral(self):
        report = new_report("domain", "AZ", "example.com", "example.com")
        with patch("forensics.domain.fetch_https", side_effect=[(200, {}, document(REGISTRAR)), (503, {}, b"unavailable")]):
            add_rdap_section(report, "Domain-RDAP / Registrierungsdaten", REGISTRY, ["registry.example"], follow_domain="example.com")
        self.assertEqual(report["sections"][0]["status"], "unavailable")
        self.assertIn(["Kennung", "DOMAIN-123"], report["sections"][1]["rows"])
        self.assertEqual(report["sections"][2]["status"], "unavailable")
        self.assertEqual(report["sources"], [REGISTRY, REGISTRAR])
