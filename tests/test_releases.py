import io
import json
from copy import deepcopy
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

from django.test import Client, SimpleTestCase, override_settings

from webforensics.releases import API_URL, ReleaseError, check_latest_release, fetch_latest_release

RELEASE = {"tag_name": "v1.2.3", "draft": False, "prerelease": False, "published_at": "2026-11-06T12:00:00Z", "html_url": "javascript:bad", "target_commitish": "main", "body": "<script>ignored</script>"}


class ReleaseTests(SimpleTestCase):
    def result(self, release, current="1.0.0"):
        with patch("webforensics.releases.fetch_latest_release", return_value=release), patch("webforensics.releases.__version__", current):
            return check_latest_release()

    def test_new_published_release_generates_only_tag_update(self):
        result = self.result(RELEASE)
        self.assertEqual(result["status"], "update_available")
        commands = " &&\n".join(result["instructions"])
        self.assertIn('test -z "$(git status --porcelain)"', commands)
        self.assertIn("refs/tags/v1.2.3:refs/tags/v1.2.3", commands)
        self.assertIn("git switch --detach refs/tags/v1.2.3", commands)
        self.assertNotIn("main", commands)
        self.assertNotIn("git pull", commands)
        self.assertNotIn("reset --hard", commands)
        self.assertEqual(result["release"]["url"], "https://github.com/gl1tchb1rd/web_forensics/releases/tag/v1.2.3")

    def test_equal_and_newer_installations_never_get_upgrade_commands(self):
        for current, status in (("1.2.3", "current"), ("2.0.0", "ahead")):
            with self.subTest(current=current):
                result = self.result(RELEASE, current)
                self.assertEqual(result["status"], status)
                self.assertEqual(result["instructions"], [])

    def test_numeric_comparison_is_not_lexicographic(self):
        release = dict(RELEASE, tag_name="v1.10.0")
        self.assertEqual(self.result(release, "1.9.9")["status"], "update_available")

    def test_drafts_prereleases_and_unpublished_releases_are_excluded(self):
        for fields in ({"draft": True}, {"prerelease": True}, {"published_at": None}):
            result = self.result(dict(RELEASE, **fields))
            self.assertEqual(result["status"], "no_release")
            self.assertEqual(result["instructions"], [])

    def test_no_release_is_distinct_from_an_error(self):
        self.assertEqual(self.result(None)["status"], "no_release")
        with self.assertRaises(ReleaseError):
            self.result({"message": "not a release"})

    def test_invalid_tags_cannot_inject_shell_commands(self):
        for tag in ("v1.2.3;rm -rf /", "$(echo bad)", "--help", "main", "../v1.2.3", "v1.2.3\n", "v01.2.3", "v1.2.3-rc1", "a" * 81):
            with self.subTest(tag=tag):
                result = self.result(dict(RELEASE, tag_name=tag))
                self.assertEqual(result["status"], "unsupported_version")
                self.assertEqual(result["instructions"], [])

    def test_build_metadata_does_not_raise_semver_precedence(self):
        result = self.result(dict(RELEASE, tag_name="1.2.3+build.9"), "1.2.3")
        self.assertEqual(result["status"], "current")

    def test_malformed_publishing_date_is_not_a_release(self):
        with self.assertRaises(ReleaseError):
            self.result(dict(RELEASE, published_at="invalid"))

    def test_check_does_not_execute_update_commands(self):
        with patch("subprocess.run") as run:
            self.result(RELEASE)
        run.assert_not_called()

    def test_fixed_release_api_request_and_no_branch_or_tag_api(self):
        response = MagicMock()
        response.status = 200
        response.read1.side_effect = [json.dumps(RELEASE).encode(), b""]
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with patch("webforensics.releases.build_opener", return_value=opener):
            self.assertEqual(fetch_latest_release()["tag_name"], "v1.2.3")
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, API_URL)
        self.assertTrue(request.full_url.endswith("/releases/latest"))
        self.assertIsNone(request.data)
        self.assertNotIn("Authorization", request.headers)
        self.assertNotIn("Cookie", request.headers)
        self.assertNotIn("1.0.0", request.headers["User-agent"])

    def test_rate_limit_and_network_error_never_look_like_current(self):
        for error in (HTTPError(API_URL, 403, "limited", {"X-RateLimit-Remaining": "0"}, io.BytesIO()), URLError("blocked")):
            with patch("webforensics.releases.build_opener") as build:
                build.return_value.open.side_effect = error
                with self.assertRaises(ReleaseError):
                    fetch_latest_release()

    def test_404_means_no_public_release(self):
        with patch("webforensics.releases.build_opener") as build:
            build.return_value.open.side_effect = HTTPError(API_URL, 404, "not found", {}, io.BytesIO())
            self.assertIsNone(fetch_latest_release())

    def test_oversized_response_is_rejected(self):
        response = MagicMock()
        response.status = 200
        response.read1.return_value = b"x" * 16384
        with patch("webforensics.releases.build_opener") as build:
            build.return_value.open.return_value.__enter__.return_value = response
            with self.assertRaisesRegex(ReleaseError, "groß"):
                fetch_latest_release()


@override_settings(ALLOWED_HOSTS=["testserver"], WF_AUTH_ENABLED=False, PUBLIC_HTTPS=False)
class ReleaseEndpointTests(SimpleTestCase):
    def test_loading_home_never_checks_for_releases(self):
        with patch("webforensics.views.check_latest_release") as check:
            self.assertEqual(self.client.get("/").status_code, 200)
        check.assert_not_called()

    def test_explicit_check_returns_metadata_without_server_action(self):
        with patch("webforensics.releases.fetch_latest_release", return_value=deepcopy(RELEASE)):
            response = self.client.post("/api/releases/check", data="{}", content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "update_available")
        self.assertEqual(response.headers["Cache-Control"], "no-store, max-age=0")

    def test_csrf_is_required(self):
        response = Client(enforce_csrf_checks=True).post("/api/releases/check", data="{}", content_type="application/json")
        self.assertEqual(response.status_code, 403)

    def test_no_investigation_inputs_accepted(self):
        with patch("webforensics.views.check_latest_release") as check:
            response = self.client.post("/api/releases/check", data='{"header":"private"}', content_type="application/json")
        self.assertEqual(response.status_code, 400)
        check.assert_not_called()

    def test_errors_are_reported_without_marking_up_to_date(self):
        with patch("webforensics.views.check_latest_release", side_effect=ReleaseError("Netzwerk nicht verfügbar.")):
            response = self.client.post("/api/releases/check", data="{}", content_type="application/json")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"error": "Netzwerk nicht verfügbar."})
