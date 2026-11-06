import json
import re

from django.conf import settings
from django.test import Client, SimpleTestCase, override_settings
from django.middleware.csrf import get_token
from django.test import RequestFactory

from tests.test_headers import HEADER


@override_settings(ALLOWED_HOSTS=["forensics.example", "127.0.0.1"], WF_AUTH_ENABLED=False,
                   PUBLIC_HTTPS=False, CSRF_COOKIE_SECURE=False, CSRF_TRUSTED_ORIGINS=[])
class DeploymentCsrfTests(SimpleTestCase):
    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)
        self.data = json.dumps({"module": "headers", "case": "CSRF-TEST", "input": HEADER})

    def page_token(self, host="forensics.example", secure=False):
        page = self.client.get("/", HTTP_HOST=host, secure=secure)
        self.assertEqual(page.status_code, 200)
        return re.search(r'name="csrf-token" content="([^"]+)"', page.content.decode())[1]

    def post(self, token, origin="https://forensics.example", host="forensics.example", **kwargs):
        return self.client.post("/api/analyze", data=self.data, content_type="application/json", HTTP_HOST=host, HTTP_ORIGIN=origin, HTTP_X_CSRFTOKEN=token, **kwargs)

    @override_settings(PUBLIC_HTTPS=True, CSRF_COOKIE_SECURE=True, CSRF_TRUSTED_ORIGINS=[])
    def test_https_browser_to_http_backend_accepts_same_origin(self):
        token = self.page_token()
        self.assertTrue(self.client.cookies[settings.CSRF_COOKIE_NAME]["secure"])
        response = self.post(token)
        self.assertEqual(response.status_code, 200, response.content.decode())

    @override_settings(PUBLIC_HTTPS=True, CSRF_COOKIE_SECURE=True, CSRF_TRUSTED_ORIGINS=[])
    def test_https_proxy_accepts_browser_port_from_preserved_host(self):
        token = self.page_token(host="forensics.example:8443")
        self.assertEqual(self.post(token, origin="https://forensics.example:8443", host="forensics.example:8443").status_code, 200)

    @override_settings(PUBLIC_HTTPS=True, CSRF_COOKIE_SECURE=True, CSRF_TRUSTED_ORIGINS=[])
    def test_https_proxy_still_rejects_foreign_origin(self):
        token = self.page_token()
        response = self.post(token, origin="https://untrusted.example")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["code"], "csrf_origin_mismatch")
        self.assertNotIn("untrusted.example", response.content.decode())

    @override_settings(PUBLIC_HTTPS=False, CSRF_COOKIE_SECURE=False, CSRF_TRUSTED_ORIGINS=[])
    def test_http_browser_still_works(self):
        token = self.page_token()
        self.assertFalse(self.client.cookies[settings.CSRF_COOKIE_NAME]["secure"])
        self.assertEqual(self.post(token, origin="http://forensics.example").status_code, 200)

    @override_settings(PUBLIC_HTTPS=False, CSRF_COOKIE_SECURE=False, CSRF_TRUSTED_ORIGINS=[])
    def test_forwarded_scheme_does_not_change_security_mode(self):
        token = self.page_token()
        response = self.post(token, HTTP_X_FORWARDED_PROTO="https")
        self.assertEqual(response.status_code, 403)

    @override_settings(PUBLIC_HTTPS=True, CSRF_COOKIE_SECURE=True, CSRF_TRUSTED_ORIGINS=[])
    def test_missing_cookie_has_actionable_error(self):
        token = self.page_token()
        self.client.cookies.clear()
        response = self.post(token)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["code"], "csrf_cookie_missing")
        self.assertIn("Cookies", response.json()["error"])

    @override_settings(PUBLIC_HTTPS=True, CSRF_COOKIE_SECURE=True, CSRF_TRUSTED_ORIGINS=[])
    def test_http_request_in_https_mode_explains_configuration(self):
        token = self.page_token()
        response = self.post(token, origin="http://forensics.example")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["code"], "csrf_https_mismatch")
        self.assertIn("WF_HTTPS=0", response.json()["error"])

    @override_settings(PUBLIC_HTTPS=True, CSRF_COOKIE_SECURE=True, CSRF_TRUSTED_ORIGINS=[])
    def test_invalid_token_has_own_error(self):
        self.page_token()
        other_request = RequestFactory().get("/")
        response = self.post(get_token(other_request))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["code"], "csrf_token_invalid")

    @override_settings(PUBLIC_HTTPS=True, CSRF_COOKIE_SECURE=True, CSRF_TRUSTED_ORIGINS=[])
    def test_originless_https_request_still_requires_trusted_referer(self):
        token = self.page_token()
        response = self.client.post("/api/analyze", data=self.data, content_type="application/json", HTTP_HOST="forensics.example", HTTP_X_CSRFTOKEN=token)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["code"], "csrf_referer_invalid")

    def test_invalid_host_is_reported_before_serving_page(self):
        response = self.client.get("/", HTTP_HOST="unlisted.example")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["code"], "invalid_host")
        self.assertIn("WF_ALLOWED_HOSTS", response.json()["error"])

    def test_another_django_application_cookie_cannot_replace_this_cookie(self):
        token = self.page_token()
        self.assertEqual(settings.CSRF_COOKIE_NAME, "wf_csrftoken")
        self.client.cookies["csrftoken"] = "invalid-token-from-another-app"
        self.assertEqual(self.post(token, origin="http://forensics.example").status_code, 200)
