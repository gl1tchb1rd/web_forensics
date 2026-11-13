"""Synthetic DENIC pages, using the labelled structure from domain_analysis.py."""
import hashlib
import io
import json
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings
from pypdf import PdfReader

from forensics.denic import add_denic_webwhois, parse_denic_webwhois
from forensics.domain import analyze_domain, make_plan
from forensics.network import NetworkError, network_budget
from forensics.report import new_report


PUBLIC_HTML = """<!doctype html><html><head><meta charset="utf-8">
<script>Informationen zum Domaininhaber Name FALSE SCRIPT NAME</script></head><body>
<h1>Domainabfrage</h1><p>Domain: example.de</p><p>Die Domain ist bereits registriert.</p>
<div>Datum der letzten Registrierung</div><div>01.02.2003</div>
<div>Letzte Aktualisierung: 04.05.2026</div>
<h2>Informationen zum Domaininhaber</h2>
<dl><dt>Name</dt><dd>Beispielverein e. V.</dd><dt>Adresse</dt><dd>Musterstraße 1</dd>
<dt>Postleitzahl</dt><dd>12345</dd><dt>Ort</dt><dd>Beispielstadt</dd><dt>Land</dt><dd>DE</dd>
<dt>E-Mail</dt><dd>kontakt@example.de</dd><dt>Telefon</dt><dd>+49 123 4567</dd></dl>
<h2>Hinweis für Domaininhaber</h2><p>Name: NOT A HOLDER</p>
<h2>Informationen zur Domainverwaltung</h2><dl><dt>Name</dt><dd>Beispielregistrar GmbH</dd>
<dt>Adresse</dt><dd>Mitgliederweg 2</dd><dt>Ort</dt><dd>Frankfurt am Main</dd>
<dt>E-Mail</dt><dd>registrar@example.org</dd></dl>
<h2>Technische Daten</h2><p>Name: NOT A REGISTRAR</p></body></html>"""
PRIVATE_HTML = """<h1>Domain: example.de</h1><p>Die Domain ist bereits registriert.</p>
<h2>Informationen zum Domaininhaber</h2><p>Diese Daten sind nicht öffentlich zugänglich.</p>
<h2>Hinweis für Dritte</h2><p>Name: NO HOLDER HERE</p>
<h2>Informationen zur Domainverwaltung</h2><p>Name: Beispielregistrar GmbH</p>
<h2>Technische Daten</h2>"""


def dns_empty(domain, kind):
    return {"kind": kind, "values": [], "status": "empty", "note": ""}


class DenicTests(SimpleTestCase):
    def setUp(self):
        self.report = new_report("domain", "TEST", "example.de", "example.de")

    def fetch(self, html=PUBLIC_HTML, status=200, headers=None):
        return patch("forensics.denic.fetch_https", return_value=(status, headers or {"Content-Type": "text/html; charset=utf-8"}, html.encode()))

    def test_public_holder_member_dates_and_boundaries(self):
        data = parse_denic_webwhois(PUBLIC_HTML, "example.de")
        self.assertTrue(data["recognized"])
        self.assertEqual(data["domain_holder"]["name"], "Beispielverein e. V.")
        self.assertEqual(data["domain_holder"]["address"], "Musterstraße 1")
        self.assertEqual(data["domain_holder"]["email"], "kontakt@example.de")
        self.assertEqual(data["managing_denic_member"]["name"], "Beispielregistrar GmbH")
        self.assertEqual(data["registration_date"], "01.02.2003")
        self.assertEqual(data["last_update"], "04.05.2026")
        self.assertNotIn("NOT A", str(data))
        self.assertNotIn("FALSE SCRIPT", str(data))

    def test_private_holder_is_not_confused_with_public_managing_member(self):
        data = parse_denic_webwhois(PRIVATE_HTML, "example.de")
        self.assertEqual(data["domain_holder"], {"visibility": "not_public"})
        self.assertEqual(data["managing_denic_member"]["name"], "Beispielregistrar GmbH")
        with self.fetch(PRIVATE_HTML):
            add_denic_webwhois(self.report, "example.de")
        rows = dict(self.report["sections"][0]["rows"])
        self.assertIn("ausdrücklich als nicht öffentlich", rows["Domaininhaber"])
        self.assertNotIn("Domaininhaber / Name", rows)

    def test_inline_labels_colons_nested_names_and_multiline_address(self):
        html = """<h2>Informationen zum Domaininhaber</h2><dt>Name:</dt>
<dd><span>Beispielverein</span> <strong>e. V.</strong></dd>
<dt>Adresse:</dt><dd>Musterstraße 1<br>Gebäude B</dd><div>Ort: Beispielstadt</div>
<h2>Informationen zur Domainverwaltung</h2><p>Name: Registrar GmbH</p><h2>Technische Daten</h2>"""
        holder = parse_denic_webwhois(html, "example.de")["domain_holder"]
        self.assertEqual(holder["name"].replace("\n", " "), "Beispielverein e. V.")
        self.assertEqual(holder["address"], "Musterstraße 1\nGebäude B")
        self.assertEqual(holder["city"], "Beispielstadt")

    def test_query_matches_original_analyzer_and_preserves_response_hash(self):
        with self.fetch() as fetch:
            add_denic_webwhois(self.report, "example.de")
        url = fetch.call_args.args[0]
        self.assertEqual(url, "https://webwhois.denic.de/?lang=de&query=example.de")
        self.assertIn("text/html", fetch.call_args.kwargs["accept"])
        item = self.report["sections"][0]
        self.assertEqual(item["status"], "ok")
        self.assertEqual(item["raw"], PUBLIC_HTML)
        self.assertIn(["SHA-256 der HTML-Antwortbytes", hashlib.sha256(PUBLIC_HTML.encode()).hexdigest()], item["rows"])
        self.assertEqual(self.report["sources"], [url])
        self.assertTrue(any("öffentlicher Domaininhaber: Beispielverein e. V." in item["text"] for item in self.report["summary"]))

    def test_unknown_page_and_challenge_are_unavailable_without_invented_privacy_status(self):
        for html in ("<h1>Domainabfrage</h1><input name='query' value='example.de'>", "<h1>Please complete the CAPTCHA</h1>"):
            with self.subTest(html=html), self.fetch(html):
                report = new_report("domain", "TEST", "example.de", "example.de")
                add_denic_webwhois(report, "example.de")
                self.assertEqual(report["sections"][0]["status"], "unavailable")
                self.assertNotIn("nicht öffentlich", str(report["sections"][0]["rows"]))

    def test_unregistered_domain_is_an_empty_result(self):
        with self.fetch("<p>Die Domain example.de ist frei.</p>"):
            add_denic_webwhois(self.report, "example.de")
        self.assertEqual(self.report["sections"][0]["status"], "empty")
        self.assertIn(["Domainstatus", "Laut DENIC verfügbar"], self.report["sections"][0]["rows"])

    def test_mismatched_result_domain_is_rejected(self):
        with self.fetch(PUBLIC_HTML.replace("Domain: example.de", "Domain: other.de")):
            add_denic_webwhois(self.report, "example.de")
        self.assertEqual(self.report["sections"][0]["status"], "unavailable")
        self.assertNotIn("Beispielverein", str(self.report["sections"][0]["rows"]))

    def test_http_errors_keep_status_and_raw_response(self):
        with self.fetch("<h1>Rate limit</h1>", status=429):
            add_denic_webwhois(self.report, "example.de")
        item = self.report["sections"][0]
        self.assertEqual(item["status"], "unavailable")
        self.assertIn("429", item["note"])
        self.assertEqual(item["raw"], "<h1>Rate limit</h1>")

    def test_redirect_must_stay_on_denic_https_and_same_query_domain(self):
        initial = "https://webwhois.denic.de/?lang=de&query=example.de"
        for url in ("https://unknown.example/", "http://webwhois.denic.de/", "https://webwhois.denic.de:22/", "https://webwhois.denic.de/?query=other.de"):
            with self.subTest(url=url), self.fetch("", 302, {"Location": url}) as fetch:
                report = new_report("domain", "TEST", "example.de", "example.de")
                add_denic_webwhois(report, "example.de")
                fetch.assert_called_once()
                self.assertEqual(report["sections"][0]["source"], initial)
                self.assertEqual(report["sections"][0]["status"], "unavailable")

    def test_same_host_redirect_is_followed(self):
        with patch("forensics.denic.fetch_https", side_effect=[(302, {"Location": "/result?query=example.de&lang=de"}, b""), (200, {}, PUBLIC_HTML.encode())]) as fetch:
            add_denic_webwhois(self.report, "example.de")
        self.assertEqual(fetch.call_count, 2)
        self.assertEqual(self.report["sections"][0]["status"], "ok")

    def test_exhausted_budget_does_not_start_lookup(self):
        with network_budget(-1), self.fetch() as fetch:
            add_denic_webwhois(self.report, "example.de")
        fetch.assert_not_called()
        self.assertEqual(self.report["sources"], [])

    def test_plan_discloses_webwhois_without_sending_domain(self):
        with patch("forensics.denic.fetch_https") as fetch, patch("forensics.whois.open_whois") as tcp:
            plan = make_plan("domain", "www.example.de", {"whois": True})
        fetch.assert_not_called()
        tcp.assert_not_called()
        self.assertTrue(plan["denic_webwhois"])
        self.assertTrue(any("webwhois.denic.de" in row[1] and "example.de" in row[2] for row in plan["recipients"]))
        self.assertFalse(make_plan("domain", "example.de", {})["denic_webwhois"])

    def test_web_lookup_runs_before_dns_and_tcp_and_survives_tcp_failure(self):
        plan = make_plan("domain", "www.example.de", {"whois": True})
        seen = []
        def web(url, **kwargs):
            seen.append("web")
            return 200, {}, PUBLIC_HTML.encode()
        def dns(domain, kind):
            self.assertTrue(seen)
            return dns_empty(domain, kind)
        with patch("forensics.denic.fetch_https", side_effect=web), patch("forensics.domain.dns_record", side_effect=dns), patch("forensics.whois.open_whois", side_effect=NetworkError("TCP 43 blocked")):
            report = analyze_domain("TEST", "www.example.de", plan)
        lookup = next(item for item in report["sections"] if item["title"].startswith("DENIC-Web"))
        self.assertEqual(lookup["status"], "ok")
        self.assertIn(["Domaininhaber / Name", "Beispielverein e. V."], lookup["rows"])

    def test_old_plan_does_not_silently_gain_new_recipient(self):
        plan = {"options": {"rdap": True}, "recipients": [], "errors": [], "provider": None}
        with self.fetch() as fetch, patch("forensics.domain.dns_record", side_effect=dns_empty):
            analyze_domain("TEST", "example.de", plan)
        fetch.assert_not_called()

    @override_settings(ALLOWED_HOSTS=["testserver"])
    def test_signed_plan_to_analysis_and_pdf_shows_holder_and_member(self):
        def post(path, value):
            return self.client.post(path, data=json.dumps(value), content_type="application/json")
        planned = post("/api/plan", {"module": "domain", "domain": "example.de", "options": {"whois": True}})
        self.assertEqual(planned.status_code, 200)
        with self.fetch(), patch("forensics.domain.dns_record", side_effect=dns_empty), patch("forensics.whois.open_whois", side_effect=NetworkError("TCP 43 blocked")):
            result = post("/api/analyze", {"module": "domain", "input": "example.de", "case": "TEST", "consent": True, "plan_token": planned.json()["token"]})
        self.assertEqual(result.status_code, 200)
        pdf = post("/api/report.pdf", {"token": result.json()["token"]})
        self.assertEqual(pdf.status_code, 200)
        text = " ".join(" ".join(page.extract_text() for page in PdfReader(io.BytesIO(pdf.content)).pages).split())
        self.assertIn("Beispielverein e. V.", text)
        self.assertIn("Beispielregistrar GmbH", text)
        self.assertIn("SHA-256 der HTML-Antwortbytes", text)
