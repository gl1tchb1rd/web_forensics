"""Optional shared HTTP Basic credentials; no accounts or stored sessions."""
import base64
import binascii
import hashlib
import secrets

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import JsonResponse
from django.utils.cache import patch_vary_headers


def load_auth_config(environ):
    flag = environ.get("WF_AUTH_ENABLED", "0").strip().lower()
    if flag not in ("0", "false", "no", "off", "1", "true", "yes", "on"):
        raise ImproperlyConfigured("WF_AUTH_ENABLED muss 0 oder 1 sein (alternativ false/true, no/yes, off/on).")
    enabled = flag in ("1", "true", "yes", "on")
    username = environ.get("WF_AUTH_USERNAME", "admin")
    password = environ.get("WF_AUTH_PASSWORD", "")
    if enabled:
        if not username.strip() or len(username) > 128 or ":" in username or any(ord(c) < 32 or ord(c) == 127 for c in username):
            raise ImproperlyConfigured("WF_AUTH_USERNAME muss 1–128 Zeichen ohne Doppelpunkt oder Steuerzeichen enthalten.")
        if not password.strip() or len(password) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in password):
            raise ImproperlyConfigured("Bei aktiviertem Passwortschutz muss WF_AUTH_PASSWORD mit 1–1024 Zeichen ohne Steuerzeichen gesetzt sein.")
    return enabled, username, password


def valid_credentials(header):
    if len(header) > 8192:
        return False
    scheme, separator, encoded = header.partition(" ")
    if not separator or scheme.lower() != "basic":
        return False
    try:
        decoded = base64.b64decode(encoded.strip(), validate=True)
    except (binascii.Error, ValueError, UnicodeError):
        return False
    username, separator, password = decoded.partition(b":")
    if not separator:
        return False
    # Both comparisons execute; fixed-size digests support UTF-8 credentials.
    user_ok = secrets.compare_digest(hashlib.sha256(username).digest(), hashlib.sha256(settings.WF_AUTH_USERNAME.encode("utf-8")).digest())
    password_ok = secrets.compare_digest(hashlib.sha256(password).digest(), hashlib.sha256(settings.WF_AUTH_PASSWORD.encode("utf-8")).digest())
    return user_ok and password_ok


class BasicAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not settings.WF_AUTH_ENABLED or request.path_info == "/healthz":
            return self.get_response(request)
        if valid_credentials(request.META.get("HTTP_AUTHORIZATION", "")):
            response = self.get_response(request)
        else:
            response = JsonResponse({"error": "Zugriff geschützt. Bitte mit Benutzername und Passwort anmelden."}, status=401)
            response["WWW-Authenticate"] = 'Basic realm="Web Forensics", charset="UTF-8"'
        patch_vary_headers(response, ("Authorization",))
        return response
