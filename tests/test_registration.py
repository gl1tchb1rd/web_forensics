"""Synthetic protocol examples; no live domain data or external requests."""
import hashlib
import io
import json
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings
from pypdf import PdfReader

from forensics.domain import (
    REGISTRAR_DIRECTORY, analyze_domain, domain_provider, make_plan,
    rdap_rows, registrar_directory, registrar_query,
)
from forensics.network import NetworkError


DOMAIN = "hofmann-net.com"
REGISTRY = "https://registry.example/"
REGISTRAR = "https://registrar.example/rdap/"
DIRECTORY = b"ID,Registrar Name,Status,RDAP Base URL\r\n83,Example Registrar,Accredited,https://registrar.example/rdap/\r\n"


def registry_data():
    return {"objectClassName": "domain", "ldhName": DOMAIN.upper(), "status": ["active"],
            "entities": [{"roles": ["registrar"], "handle": "83",
                          "publicIds": [{"type": "IANA Registrar ID", "identifier": "83"}]}]}


def registrar_data():
    return {"objectClassName": "domain", "ldhName": DOMAIN,
            "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [
                ["fn", {}, "text", "REDACTED FOR PRIVACY"],
                ["org", {}, "text", ["REDACTED FOR PRIVACY"]],
            ]]}],
            "notices": [{"title": "Data redacted", "description": ["Personal data is withheld."]}],
            "redacted": [{"name": {"type": "Registrant Name"}, "reason": {"description": "Server policy"}}]}


def dns_answer(domain, kind):
    return {"kind": kind, "values": [], "status": "empty", "note": "Kein Eintrag dieses Typs."}


class RegistrationTests(SimpleTestCase):
    def setUp(self):
        registrar_directory.cache_clear()
        self.addCleanup(registrar_directory.cache_clear)
        self.resolver = patch("forensics.domain.resolver_description", return_value="Testresolver")
        self.resolver.start()
        self.addCleanup(self.resolver.stop)

    def plan(self):
        return {"options": {"rdap": True}, "recipients": [], "errors": [], "provider": REGISTRY,
                "allowed_rdap_hosts": ["registry.example", "registrar.example"],
                "registrars": {"83": REGISTRAR}}

    def analyze(self, plan, fetch, domain=DOMAIN):
        with patch("forensics.domain.dns_record", side_effect=dns_answer), patch("forensics.domain.fetch_https", side_effect=fetch):
            return analyze_domain("TEST", domain, plan)

    def test_de_provider_does_not_depend_on_iana_bootstrap(self):
        with patch("forensics.domain.bootstrap") as bootstrap, patch("forensics.domain.registrar_directory") as directory:
            self.assertEqual(domain_provider("feuerwehr-vestenberg.de"), "https://rdap.denic.de/")
            plan = make_plan("domain", "feuerwehr-vestenberg.de", {"rdap": True})
        bootstrap.assert_not_called()
        directory.assert_not_called()
        self.assertEqual(plan["allowed_rdap_hosts"], ["rdap.denic.de"])
        self.assertEqual(plan["errors"], [])
        self.assertTrue(any(row[0] == "Domain-RDAP" and row[1] == "rdap.denic.de" and "feuerwehr-vestenberg.de" in row[2] for row in plan["recipients"]))

    def test_com_plan_discloses_registrars_without_sending_domain(self):
        with patch("forensics.domain.bootstrap", return_value=[[["com"], [REGISTRY]]]), patch("forensics.domain.fetch_https", return_value=(200, {}, DIRECTORY)) as request:
            plan = make_plan("domain", DOMAIN, {"rdap": True})
        request.assert_called_once_with(REGISTRAR_DIRECTORY)
        self.assertEqual(plan["registrars"], {"83": REGISTRAR})
        self.assertIn("registrar.example", plan["allowed_rdap_hosts"])
        self.assertTrue(any(row[0].startswith("Registrar-RDAP") and "registrar.example" in row[1] for row in plan["recipients"]))

    def test_unavailable_registrar_directory_preserves_registry_plan(self):
        with patch("forensics.domain.bootstrap", return_value=[[["com"], [REGISTRY]]]), patch("forensics.domain.registrar_directory", side_effect=NetworkError("HTTP 503")):
            plan = make_plan("domain", DOMAIN, {"rdap": True})
        self.assertEqual(plan["provider"], REGISTRY)
        self.assertEqual(plan["registrars"], {})
        self.assertIn("Registry-Abfrage bleibt möglich", plan["errors"][0])

    def test_directory_rejects_unsafe_and_terminated_entries(self):
        directory = DIRECTORY + b"84,Unsafe,Accredited,http://bad.example/\r\n85,Terminated,Terminated,https://old.example/\r\n86,Wrong port,Accredited,https://bad.example:22/\r\n87,Credentials,Accredited,https://user:password@bad.example/\r\n"
        with patch("forensics.domain.fetch_https", return_value=(200, {}, directory)):
            self.assertEqual(registrar_directory(), {"83": REGISTRAR})

    def test_invalid_directory_is_not_silently_cached_as_empty(self):
        with patch("forensics.domain.fetch_https", side_effect=[(200, {}, b"<html>error</html>"), (200, {}, DIRECTORY)]) as request:
            with self.assertRaises(NetworkError):
                registrar_directory()
            self.assertEqual(registrar_directory(), {"83": REGISTRAR})
        self.assertEqual(request.call_count, 2)

    def test_com_queries_registrar_and_preserves_privacy_data_and_evidence(self):
        responses = [registry_data(), registrar_data()]
        urls = []

        def fetch(url, **kwargs):
            urls.append(url)
            return 200, {}, json.dumps(responses[len(urls) - 1]).encode()

        report = self.analyze(self.plan(), fetch)
        self.assertEqual(urls, [REGISTRY + "domain/" + DOMAIN, REGISTRAR + "domain/" + DOMAIN])
        registrar = next(s for s in report["sections"] if s["title"].startswith("Registrar-RDAP"))
        self.assertEqual(registrar["status"], "ok")
        self.assertIn(["registrant", "REDACTED FOR PRIVACY"], registrar["rows"])
        self.assertTrue(any("Server policy" in value for _, value in registrar["rows"]))
        self.assertTrue(any("Personal data is withheld." in value for _, value in registrar["rows"]))
        self.assertIn(hashlib.sha256(json.dumps(responses[1]).encode()).hexdigest(), registrar["note"])
        self.assertIn(urls[1], report["sources"])

    def test_registrar_failure_does_not_discard_registry(self):
        def fetch(url, **kwargs):
            if url.startswith(REGISTRAR):
                return 429, {}, b"rate limited"
            return 200, {}, json.dumps(registry_data()).encode()

        report = self.analyze(self.plan(), fetch)
        registry = next(s for s in report["sections"] if s["title"].startswith("Domain-RDAP"))
        registrar = next(s for s in report["sections"] if s["title"].startswith("Registrar-RDAP"))
        self.assertEqual(registry["status"], "ok")
        self.assertEqual(registrar["status"], "unavailable")
        self.assertIn("429", registrar["note"])

    def test_unknown_registrar_link_is_not_contacted(self):
        data = registry_data()
        data["entities"][0]["publicIds"][0]["identifier"] = "99999"
        data["links"] = [{"rel": "related", "type": "application/rdap+json", "href": "https://unknown.example/domain/" + DOMAIN}]
        with patch("forensics.domain.fetch_https", return_value=(200, {}, json.dumps(data).encode())) as request, patch("forensics.domain.dns_record", side_effect=dns_answer):
            analyze_domain("TEST", DOMAIN, self.plan())
        request.assert_called_once()

    def test_related_link_must_match_approved_base_and_domain(self):
        data = {"links": [{"rel": "related", "type": "application/rdap+json", "href": REGISTRAR + "domain/" + DOMAIN}]}
        self.assertEqual(registrar_query(data, DOMAIN, self.plan()), REGISTRAR + "domain/" + DOMAIN)
        for url in (REGISTRAR + "domain/other.com", REGISTRAR + "entity/83", "http://registrar.example/rdap/domain/" + DOMAIN):
            data["links"][0]["href"] = url
            self.assertIsNone(registrar_query(data, DOMAIN, self.plan()))

    def test_registrar_redirect_outside_plan_is_blocked(self):
        urls = []

        def fetch(url, **kwargs):
            urls.append(url)
            if url.startswith(REGISTRY):
                return 200, {}, json.dumps(registry_data()).encode()
            return 302, {"Location": "https://unknown.example/domain/" + DOMAIN}, b""

        report = self.analyze(self.plan(), fetch)
        self.assertEqual(len(urls), 2)
        self.assertIn("nicht im Abfrageplan", report["sections"][-1]["note"])

    def test_mismatched_domain_response_is_not_accepted(self):
        data = registry_data()
        data["ldhName"] = "other.com"
        report = self.analyze(self.plan(), lambda *args, **kwargs: (200, {}, json.dumps(data).encode()))
        registration = next(s for s in report["sections"] if s["title"].startswith("Domain-RDAP"))
        self.assertEqual(registration["status"], "unavailable")
        self.assertEqual(registration["rows"], [])

    def test_de_keeps_technical_data_and_distinguishes_manual_holder_lookup(self):
        domain = "feuerwehr-vestenberg.de"
        plan = {"options": {"rdap": True}, "recipients": [], "errors": [], "provider": "https://rdap.denic.de/", "allowed_rdap_hosts": ["rdap.denic.de"]}
        data = {"ldhName": domain, "nameservers": [{"ldhName": "ns.example.org"}], "status": ["active"]}
        report = self.analyze(plan, lambda *args, **kwargs: (200, {}, json.dumps(data).encode()), domain)
        registration = next(s for s in report["sections"] if s["title"].startswith("Domain-RDAP"))
        self.assertEqual(registration["status"], "ok")
        self.assertIn(["Nameserver", "ns.example.org"], registration["rows"])
        self.assertNotIn("REDACTED FOR PRIVACY", str(registration))
        manual = next(s for s in report["sections"] if s["title"].startswith("DENIC-Web"))
        self.assertEqual(manual["status"], "unavailable")
        self.assertIn("Inhaberdaten nicht automatisch abgefragt", manual["note"])
        self.assertNotIn("https://webwhois.denic.de/", report["sources"])

    def test_nested_org_contacts_and_entity_remarks_are_visible(self):
        data = {"entities": [{"roles": ["registrar"], "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [
            ["org", {}, "text", ["Beispielverein", "e. V."]],
            ["adr", {"label": "Musterweg 1\n12345 Beispielstadt"}, "text", ["", "", "Musterweg 1", "Beispielstadt", "", "12345", "DE"]],
            ["email", {}, "text", "kontakt@example.org"],
        ]], "remarks": [{"title": "Disclosure", "description": ["Some fields withheld."]}]}]}]}
        rows = rdap_rows(data)
        self.assertIn(["registrant", "Beispielverein, e. V."], rows)
        self.assertIn(["registrant / Anschrift", "Musterweg 1\n12345 Beispielstadt"], rows)
        self.assertIn(["registrant / E-Mail", "kontakt@example.org"], rows)
        self.assertTrue(any("Some fields withheld." in value for _, value in rows))

    def test_optional_malformed_fields_do_not_hide_valid_domain_data(self):
        rows = rdap_rows({"ldhName": DOMAIN, "events": [None, "invalid"], "nameservers": None,
                          "notices": None, "entities": [{"roles": None, "vcardArray": None, "remarks": [None]}]})
        self.assertIn(["Domain", DOMAIN], rows)
        self.assertTrue(any("Kein öffentlicher Inhaberkontakt" in value for _, value in rows))

    @override_settings(ALLOWED_HOSTS=["testserver"])
    def test_signed_plan_analysis_and_pdf_roundtrip_with_registrar_data(self):
        def post(path, data):
            return self.client.post(path, data=json.dumps(data), content_type="application/json")

        def fetch(url, **kwargs):
            data = registrar_data() if url.startswith(REGISTRAR) else registry_data()
            return 200, {}, json.dumps(data).encode()

        with patch("forensics.domain.bootstrap", return_value=[[["com"], [REGISTRY]]]), patch("forensics.domain.registrar_directory", return_value={"83": REGISTRAR}):
            planned = post("/api/plan", {"module": "domain", "domain": DOMAIN, "options": {"rdap": True}})
        self.assertEqual(planned.status_code, 200)
        with patch("forensics.domain.dns_record", side_effect=dns_answer), patch("forensics.domain.fetch_https", side_effect=fetch):
            result = post("/api/analyze", {"module": "domain", "input": DOMAIN, "case": "TEST", "consent": True, "plan_token": planned.json()["token"]})
        self.assertEqual(result.status_code, 200)
        pdf = post("/api/report.pdf", {"token": result.json()["token"]})
        self.assertEqual(pdf.status_code, 200)
        text = "\n".join(page.extract_text() for page in PdfReader(io.BytesIO(pdf.content)).pages)
        self.assertIn("REDACTED FOR PRIVACY", text)
        self.assertIn("Server policy", text)
        self.assertIn("Registrar-RDAP", text)
