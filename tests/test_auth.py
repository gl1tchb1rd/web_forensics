import base64
import json
import secrets
from unittest.mock import patch

from django.core.exceptions import ImproperlyConfigured
from django.test import Client, SimpleTestCase, override_settings

from tests.test_headers import HEADER
from webforensics.auth import load_auth_config


def basic(username, password):
    return "Basic " + base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")


class AuthConfigTests(SimpleTestCase):
    def test_default_keeps_password_protection_off(self):
        self.assertEqual(load_auth_config({}), (False, "admin", ""))

    def test_missing_or_blank_password_prevents_enabled_startup(self):
        for password in ("", "   "):
            with self.subTest(blank_length=len(password)), self.assertRaises(ImproperlyConfigured):
                load_auth_config({"WF_AUTH_ENABLED": "1", "WF_AUTH_PASSWORD": password})

    def test_unknown_switch_does_not_disable_protection(self):
        with self.assertRaises(ImproperlyConfigured):
            load_auth_config({"WF_AUTH_ENABLED": "treu"})

    def test_invalid_username_is_rejected_without_echoing_values(self):
        password = secrets.token_urlsafe(24)
        for username in ("", " ", "user:bad", "user\nname", "a" * 129):
            with self.subTest(length=len(username)), self.assertRaises(ImproperlyConfigured) as caught:
                load_auth_config({"WF_AUTH_ENABLED": "1", "WF_AUTH_USERNAME": username, "WF_AUTH_PASSWORD": password})
            self.assertNotIn(password, str(caught.exception))

    def test_explicit_toggle_and_password_preservation(self):
        password = " " + secrets.token_urlsafe(24) + ":$# "
        for flag in ("1", "true", "on", "yes"):
            self.assertEqual(load_auth_config({"WF_AUTH_ENABLED": flag, "WF_AUTH_PASSWORD": password}), (True, "admin", password))
        for flag in ("0", "false", "off", "no"):
            self.assertFalse(load_auth_config({"WF_AUTH_ENABLED": flag})[0])


@override_settings(ALLOWED_HOSTS=["testserver"])
class PasswordProtectionTests(SimpleTestCase):
    def setUp(self):
        self.username = "test-user"
        self.password = secrets.token_urlsafe(32)
        self.config = self.settings(WF_AUTH_ENABLED=True, WF_AUTH_USERNAME=self.username, WF_AUTH_PASSWORD=self.password)
        self.config.enable()
        self.addCleanup(self.config.disable)
        self.authorization = basic(self.username, self.password)

    def test_disabled_preserves_public_landing_and_analysis(self):
        with self.settings(WF_AUTH_ENABLED=False):
            self.assertEqual(self.client.get("/").status_code, 200)
            response = self.client.post("/api/analyze", data=json.dumps({"module": "headers", "case": "AUTH-TEST", "input": HEADER}), content_type="application/json")
        self.assertEqual(response.status_code, 200)

    def test_all_routes_and_static_resources_are_protected(self):
        for method in ("get", "post"):
            for path in ("/", "/static/app.js", "/static/app.css", "/api/plan", "/api/analyze", "/api/report.pdf", "/api/releases/check", "/unknown", "/healthz/", "/healthz/../api/analyze"):
                with self.subTest(method=method, path=path):
                    response = getattr(self.client, method)(path)
                    self.assertEqual(response.status_code, 401)
                    self.assertEqual(response.headers["WWW-Authenticate"], 'Basic realm="Web Forensics", charset="UTF-8"')
                    self.assertEqual(response.headers["Cache-Control"], "no-store, max-age=0")
                    self.assertIn("Authorization", response.headers["Vary"])

    def test_public_health_is_limited_to_status_and_version(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json()), {"status", "version"})
        self.assertNotIn("WWW-Authenticate", response.headers)

    def test_correct_credentials_allow_page_and_static_resource(self):
        page = self.client.get("/", HTTP_AUTHORIZATION=self.authorization)
        self.assertContains(page, "Domainanalyse")
        self.assertIn("Authorization", page.headers["Vary"])
        self.assertNotIn(self.password, page.content.decode())
        static = self.client.get("/static/app.js", HTTP_AUTHORIZATION=self.authorization)
        self.assertEqual(static.status_code, 200)
        static.close()

    def test_invalid_credentials_and_malformed_headers_share_same_denial(self):
        expected = self.client.get("/").content
        invalid = [basic(self.username, "wrong"), basic("wrong", self.password), "Bearer token", "Basic !!!", "Basic Og==", "Basic " + base64.b64encode(b"no-colon").decode(), "Basic ☃", "Basic " + "x" * 9000]
        for header in invalid:
            with self.subTest(length=len(header)):
                response = self.client.get("/", HTTP_AUTHORIZATION=header)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.content, expected)
                self.assertNotIn(self.password, response.content.decode())

    def test_unicode_credentials_and_colons_in_password(self):
        username, password = "Prüfer", secrets.token_urlsafe(16) + ":Grüße"
        with self.settings(WF_AUTH_USERNAME=username, WF_AUTH_PASSWORD=password):
            response = self.client.get("/", HTTP_AUTHORIZATION=basic(username, password))
        self.assertEqual(response.status_code, 200)

    def test_denied_analysis_never_calls_analyzer(self):
        with patch("webforensics.views.analyze_header") as analyzer:
            response = self.client.post("/api/analyze", data=json.dumps({"module": "headers", "case": "AUTH-TEST", "input": HEADER}), content_type="application/json")
        self.assertEqual(response.status_code, 401)
        analyzer.assert_not_called()

    def test_authenticated_header_to_pdf_and_protected_download(self):
        data = self.client.post("/api/analyze", data=json.dumps({"module": "headers", "case": "AUTH-TEST", "input": HEADER}), content_type="application/json", HTTP_AUTHORIZATION=self.authorization)
        self.assertEqual(data.status_code, 200)
        token = data.json()["token"]
        denied = self.client.post("/api/report.pdf", data=json.dumps({"token": token}), content_type="application/json")
        self.assertEqual(denied.status_code, 401)
        pdf = self.client.post("/api/report.pdf", data=json.dumps({"token": token}), content_type="application/json", HTTP_AUTHORIZATION=self.authorization)
        self.assertEqual(pdf.status_code, 200)
        self.assertEqual(pdf.headers["Content-Type"], "application/pdf")
        self.assertTrue(pdf.content.startswith(b"%PDF"))

    def test_csrf_still_required_after_authentication(self):
        client = Client(enforce_csrf_checks=True)
        response = client.post("/api/analyze", data=json.dumps({"module": "headers", "case": "AUTH-TEST", "input": HEADER}), content_type="application/json", HTTP_AUTHORIZATION=self.authorization)
        self.assertEqual(response.status_code, 403)

    def test_password_change_invalidates_previous_credentials(self):
        with self.settings(WF_AUTH_PASSWORD=secrets.token_urlsafe(32)):
            self.assertEqual(self.client.get("/", HTTP_AUTHORIZATION=self.authorization).status_code, 401)
