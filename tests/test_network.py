import socket
from unittest.mock import MagicMock, patch
from django.test import SimpleTestCase
from forensics.network import NetworkError, fetch_https, is_public, network_budget, normalize_domain, open_tls, resolve_public
from forensics.domain import analyze_domain, get_rdap, make_plan


class NetworkTests(SimpleTestCase):
    def test_exhausted_request_budget_does_not_open_socket(self):
        with network_budget(-1), patch("forensics.network._socket") as dial:
            with self.assertRaisesRegex(NetworkError, "Gesamtzeitlimit"):
                open_tls("example.org", ["1.1.1.1"])
            dial.assert_not_called()

    def test_domain_normalization_and_idna(self):
        self.assertEqual(normalize_domain(" BÜCHER.DE. "), "xn--bcher-kva.de")
        self.assertEqual(normalize_domain("Example.ORG"), "example.org")

    def test_rejects_urls_ips_and_local_names(self):
        for name in ("http://example.org", "example.org:443", "localhost", "192.168.1.1", "example.local", "bad..com", "a@b.com", "example.com/a", "a\\b.com"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                normalize_domain(name)

    def test_public_address_filter_covers_tunnels_and_metadata(self):
        for ip in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "192.0.2.1", "224.0.0.1", "0.0.0.0", "::1", "fc00::1", "ff02::1", "::ffff:127.0.0.1", "64:ff9b::a00:1", "2002:7f00:1::"):
            with self.subTest(ip=ip):
                self.assertFalse(is_public(ip))
        self.assertTrue(is_public("1.1.1.1"))
        self.assertTrue(is_public("2606:4700::1111"))

    def test_private_tls_targets_blocked_before_socket(self):
        with patch("forensics.network._socket") as dial:
            with self.assertRaises(NetworkError):
                open_tls("example.org", ["127.0.0.1"])
            dial.assert_not_called()

    def test_mixed_dns_answers_blocked(self):
        fake = MagicMock()
        fake.resolve.side_effect = [["1.1.1.1", "10.1.1.1"], []]
        with patch("forensics.network.resolver", return_value=fake), self.assertRaises(NetworkError):
            resolve_public("example.org")

    def test_tls_pins_ip_and_preserves_sni_verification(self):
        raw_socket = MagicMock()
        with patch("forensics.network._socket", return_value=raw_socket) as dial, patch("forensics.network.ssl.create_default_context") as context:
            open_tls("example.org", ["1.1.1.1"])
        dial.assert_called_once_with("example.org", "1.1.1.1", 5)
        context.return_value.wrap_socket.assert_called_once_with(raw_socket, server_hostname="example.org")

    def test_proxy_connect_targets_pinned_ip(self):
        from forensics.network import _socket
        with patch("forensics.network.getproxies", return_value={"https": "http://proxy.example:8080"}), patch("forensics.network.proxy_bypass", return_value=False), patch("forensics.network.http.client.HTTPConnection") as connection:
            _socket("example.org", "1.1.1.1", 5)
        connection.return_value.set_tunnel.assert_called_once_with("1.1.1.1", 443, headers={})

    def test_unsafe_https_url_is_rejected(self):
        for url in ("http://example.org", "https://user:pass@example.org", "https://example.org:22", "https://example.org/\r\nX:bad"):
            with self.subTest(url=url), self.assertRaises(NetworkError):
                fetch_https(url)

    def test_rdap_redirect_to_undisclosed_host_is_blocked(self):
        with patch("forensics.domain.fetch_https", return_value=(302, {"Location": "https://unknown.example/ip/1.1.1.1"}, b"")) as request:
            with self.assertRaisesRegex(NetworkError, "nicht im Abfrageplan"):
                get_rdap("https://rdap.example/ip/1.1.1.1", ["rdap.example"])
            request.assert_called_once()

    def test_plan_reveals_provider_and_does_not_send_domain(self):
        with patch("forensics.domain.bootstrap", return_value=[[["org"], ["https://rdap.example/"]]]), patch("forensics.domain.registrar_directory", return_value={"1": "https://registrar.example/"}), patch("forensics.domain.resolver_description", return_value="10.0.0.53"):
            plan = make_plan("domain", "example.org", {"rdap": True})
        self.assertEqual(plan["provider"], "https://rdap.example/")
        self.assertEqual(plan["recipients"][1][1], "rdap.example")

    def test_domain_analysis_with_real_orchestration_and_recorded_responses(self):
        def dns_answer(domain, kind):
            return {"kind": kind, "values": ["1.1.1.1"] if kind == "A" else [], "status": "ok" if kind == "A" else "empty", "ttl": 300, "note": ""}
        plan = {"options": {"rdap": True, "network": False, "tls": False, "http": True}, "recipients": [], "errors": [], "provider": "https://rdap.example/", "allowed_rdap_hosts": ["rdap.example"]}
        def fetch(url, **kwargs):
            if "rdap.example" in url:
                return 200, {}, b'{"ldhName":"example.org","status":["active"]}'
            return 301, {"Location": "https://other.example/", "Server": "test"}, b""
        with patch("forensics.domain.dns_record", side_effect=dns_answer), patch("forensics.domain.fetch_https", side_effect=fetch):
            report = analyze_domain("AZ", "example.org", plan)
        self.assertTrue(any(s["title"] == "Domain-RDAP / Registrierungsdaten" and s["status"] == "ok" for s in report["sections"]))
        http = next(s for s in report["sections"] if s["title"] == "HTTPS-Antwortheader")
        self.assertIn(["HTTP-Status", "301"], http["rows"])
        self.assertIn("nicht verfolgt", http["note"])
