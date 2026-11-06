"""Bounded public HTTPS requests, pinned to checked IPs, with proxy/CA support."""
import base64
import http.client
import ipaddress
import os
import re
import socket
import ssl
import time
from contextlib import contextmanager
from contextvars import ContextVar
from urllib.parse import urlsplit
from urllib.request import getproxies, proxy_bypass

import dns.exception
import dns.resolver


class NetworkError(Exception):
    pass


_deadline = ContextVar("network_deadline", default=None)


@contextmanager
def network_budget(seconds):
    token = _deadline.set(time.monotonic() + seconds)
    try:
        yield
    finally:
        _deadline.reset(token)


def remaining(maximum):
    deadline = _deadline.get()
    if deadline is None:
        return maximum
    value = deadline - time.monotonic()
    if value <= 0:
        raise NetworkError("Das Gesamtzeitlimit der externen Abfragen wurde erreicht.")
    return min(value, maximum)


def normalize_domain(value):
    if not isinstance(value, str):
        raise ValueError("Bitte eine Domain eingeben.")
    value = value.strip().rstrip(".")
    if any(c in value for c in "/:@?#\\") or not value:
        raise ValueError("Bitte nur den Domainnamen eingeben, ohne URL, Port oder Pfad.")
    try:
        name = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("Der Domainname ist ungültig.") from None
    if len(name) > 253 or "." not in name or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in name.split(".")):
        raise ValueError("Bitte einen gültigen vollständigen Domainnamen eingeben.")
    if name.rsplit(".", 1)[-1].isdigit() or name.endswith((".localhost", ".local", ".internal", ".test", ".invalid", ".onion")):
        raise ValueError("Es werden ausschließlich öffentliche Domains unterstützt.")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    raise ValueError("Bitte eine Domain statt einer IP-Adresse eingeben.")


def is_public(value):
    address = ipaddress.ip_address(value)
    if not address.is_global or address.is_multicast or address.is_reserved:
        return False
    if address.version == 6:
        return not any(address in ipaddress.ip_network(prefix) for prefix in (
            "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32", "::ffff:0:0/96",
        ))
    return True


def resolver():
    result = dns.resolver.Resolver()
    configured = os.environ.get("WF_DNS_RESOLVERS", "")
    if configured:
        result.nameservers = [str(ipaddress.ip_address(ip.strip())) for ip in configured.split(",")]
    result.timeout = 2
    result.lifetime = remaining(3)
    return result


def resolver_description():
    return ", ".join(str(s) for s in resolver().nameservers)


def resolve_public(host):
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        addresses = []
        r = resolver()
        for record_type in ("A", "AAAA"):
            try:
                answer = r.resolve(host, record_type, search=False)
                addresses.extend(str(item) for item in answer)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except dns.exception.DNSException:
                raise NetworkError("DNS-Auflösung fehlgeschlagen oder Zeitlimit erreicht.") from None
    else:
        addresses = [str(literal)]
    if not addresses:
        raise NetworkError("Keine öffentliche Zieladresse gefunden.")
    if not all(is_public(ip) for ip in addresses):
        raise NetworkError("Zugriff gesperrt: DNS enthält nicht öffentliche oder reservierte Zieladressen.")
    return addresses


def _socket(host, ip, timeout):
    proxy_url = getproxies().get("https") if not proxy_bypass(host) else None
    if proxy_url:
        proxy = urlsplit(proxy_url)
        if proxy.scheme != "http" or not proxy.hostname:
            raise NetworkError("Der konfigurierte HTTPS-Proxy muss HTTP CONNECT unterstützen.")
        headers = {}
        if proxy.username is not None:
            from urllib.parse import unquote
            credentials = f"{unquote(proxy.username)}:{unquote(proxy.password or '')}"
            headers["Proxy-Authorization"] = "Basic " + base64.b64encode(credentials.encode()).decode()
        connection = http.client.HTTPConnection(proxy.hostname, proxy.port or 80, timeout=timeout)
        connection.set_tunnel(ip, 443, headers=headers)
        try:
            connection.connect()
        except Exception:
            connection.close()
            raise
        sock = connection.sock
        connection.sock = None
        return sock
    return socket.create_connection((ip, 443), timeout=timeout)


def open_tls(host, addresses=None, timeout=5):
    timeout = remaining(timeout)
    addresses = addresses or resolve_public(host)
    if not addresses or not all(is_public(ip) for ip in addresses):
        raise NetworkError("Nicht öffentliche Zieladresse gesperrt.")
    context = ssl.create_default_context(cafile=os.environ.get("SSL_CERT_FILE") or None)
    # Use a pinned, previously checked address; SNI and hostname verification retain the domain.
    try:
        sock = _socket(host, addresses[0], timeout)
        try:
            return context.wrap_socket(sock, server_hostname=host)
        except Exception:
            sock.close()
            raise
    except ssl.SSLCertVerificationError:
        raise NetworkError("TLS-Zertifikatsprüfung fehlgeschlagen (z. B. Vertrauenskette, Hostname oder Gültigkeit). Keine ungesicherte Wiederholung.") from None
    except (OSError, http.client.HTTPException, ssl.SSLError):
        raise NetworkError("HTTPS/TLS-Verbindung fehlgeschlagen, vom Proxy abgewiesen oder Zeitlimit erreicht.") from None


def fetch_https(url, method="GET", addresses=None, limit=1024 * 1024):
    parsed = urlsplit(url)
    try:
        valid = parsed.scheme == "https" and parsed.hostname and parsed.port in (None, 443) and not parsed.username and not parsed.password and not parsed.fragment
    except ValueError:
        valid = False
    if not valid or any(ord(c) < 33 for c in url):
        raise NetworkError("Ungültige HTTPS-Zieladresse.")
    connection = http.client.HTTPConnection(parsed.hostname, 443, timeout=remaining(5))
    response = None
    started = time.monotonic()
    try:
        connection.sock = open_tls(parsed.hostname, addresses)
        connection.request(method, parsed.path + ("?" + parsed.query if parsed.query else ""), headers={
            "Host": parsed.hostname, "User-Agent": "WebForensics/0.1", "Accept": "application/rdap+json, application/json, */*",
            "Accept-Encoding": "identity", "Connection": "close",
        })
        response = connection.getresponse()
        body = bytearray()
        if method != "HEAD":
            while True:
                remaining(5)
                if time.monotonic() - started > 12:
                    raise NetworkError("Zeitlimit beim Abruf der Antwort erreicht.")
                chunk = response.read1(min(16384, limit + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > limit:
                    raise NetworkError("Die Antwort überschreitet die zulässige Größe.")
        return response.status, dict(response.getheaders()), bytes(body)
    except NetworkError:
        raise
    except (OSError, http.client.HTTPException, UnicodeError):
        raise NetworkError("HTTPS-Abruf fehlgeschlagen oder Zeitlimit erreicht.") from None
    finally:
        if response is not None:
            response.close()
        connection.close()
