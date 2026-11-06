import io
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.core import signing
from django.test import Client, SimpleTestCase, override_settings
from pypdf import PdfReader
from forensics.headers import analyze_header
from forensics.pdf import render_pdf
from tests.test_headers import HEADER


@override_settings(ALLOWED_HOSTS=["testserver"])
class WebTests(SimpleTestCase):
    def post(self, path, data):
        return self.client.post(path, data=json.dumps(data), content_type="application/json")

    def test_health_and_landing_page(self):
        self.assertEqual(self.client.get("/healthz").json()["status"], "ok")
        page = self.client.get("/")
        self.assertContains(page, "Domainanalyse")
        self.assertContains(page, "E-Mail-Header-Analyse")
        self.assertEqual(page.headers["Cache-Control"], "no-store, max-age=0")
        self.assertIn("default-src 'self'", page.headers["Content-Security-Policy"])

    def test_case_is_required_server_side(self):
        response = self.post("/api/analyze", {"module": "headers", "input": HEADER})
        self.assertEqual(response.status_code, 400)
        self.assertIn("Aktenzeichen", response.json()["error"])

    def test_roundtrip_header_to_pdf_and_no_report_files(self):
        with tempfile.TemporaryDirectory() as tmp, patch("tempfile.tempdir", tmp):
            result = self.post("/api/analyze", {"module": "headers", "case": "123 Js 456/26", "input": HEADER})
            self.assertEqual(result.status_code, 200)
            pdf = self.post("/api/report.pdf", {"token": result.json()["token"]})
            self.assertEqual(list(Path(tmp).iterdir()), [])
        self.assertEqual(pdf.status_code, 200)
        self.assertEqual(pdf.headers["Content-Type"], "application/pdf")
        reader = PdfReader(io.BytesIO(pdf.content))
        text = "\n".join(p.extract_text() for p in reader.pages)
        self.assertIn("123 Js 456/26", text)
        self.assertIn("SHA-256", text)
        self.assertIn("<b>untrusted</b>", text)
        self.assertIn("Prüfung", text)
        self.assertIn("spf=pass", text)
        for page in reader.pages:
            self.assertIn("123 Js 456/26", page.extract_text())
        self.assertEqual(pdf.headers["Cache-Control"], "no-store, max-age=0")

    def test_report_tampering_is_rejected(self):
        report = analyze_header("AZ", HEADER)
        token = signing.dumps(report, salt="pdf-report", compress=True)
        response = self.post("/api/report.pdf", {"token": token + "tampered"})
        self.assertEqual(response.status_code, 400)

    def test_pdf_contains_input_hash_and_analysis_id(self):
        report = analyze_header("AZ", HEADER)
        text = "".join(p.extract_text() for p in PdfReader(io.BytesIO(render_pdf(report))).pages)
        self.assertIn(report["id"], text)
        self.assertIn(report["input_sha256"], text.replace("\n", ""))

    def test_external_queries_require_consent_and_valid_plan(self):
        with patch("webforensics.views.analyze_domain") as domain:
            response = self.post("/api/analyze", {"module": "domain", "case": "AZ", "input": "example.org"})
        self.assertEqual(response.status_code, 400)
        domain.assert_not_called()

    def test_plan_cannot_be_reused_for_another_domain(self):
        plan = {"module": "domain", "domain": "example.org"}
        response = self.post("/api/analyze", {"module": "domain", "case": "AZ", "input": "other.org", "consent": True, "plan_token": signing.dumps(plan, salt="query-plan")})
        self.assertEqual(response.status_code, 400)
        self.assertIn("geändert", response.json()["error"])

    def test_csrf_is_enforced(self):
        client = Client(enforce_csrf_checks=True)
        response = client.post("/api/analyze", data=json.dumps({"module": "headers", "case": "AZ", "input": HEADER}), content_type="application/json")
        self.assertEqual(response.status_code, 403)
        self.assertNotIn(HEADER, response.content.decode())

    def test_request_size_rejected_without_echoing_payload(self):
        response = self.client.post("/api/analyze", data=b"x" * (2 * 1024 * 1024 + 1), content_type="application/json")
        self.assertEqual(response.status_code, 413)

    def test_long_header_and_case_generate_multiple_pages(self):
        text = HEADER + "X-Long: " + "x" * 12000 + "\n"
        report = analyze_header("AZ-" + "L" * 90, text)
        reader = PdfReader(io.BytesIO(render_pdf(report)))
        self.assertGreater(len(reader.pages), 1)
        self.assertTrue(all("Aktenzeichen:" in p.extract_text() for p in reader.pages))

    def test_data_cannot_be_requested_via_get(self):
        self.assertEqual(self.client.get("/api/report.pdf").status_code, 405)
        self.assertEqual(self.client.get("/api/analyze").status_code, 405)
