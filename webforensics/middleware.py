from django.http import JsonResponse
from django.conf import settings
from django.core.exceptions import DisallowedHost


class DeploymentMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            request.get_host()
        except DisallowedHost:
            return JsonResponse({
                "code": "invalid_host",
                "error": "Der aufgerufene Hostname ist nicht freigegeben. Bitte die öffentliche Domain in WF_ALLOWED_HOSTS eintragen (ohne Protokoll oder Port) und den Container neu erstellen. Der Reverse-Proxy muss den öffentlichen Host-Header erhalten.",
            }, status=400)
        if settings.PUBLIC_HTTPS:
            # An explicit deployment setting, never inferred from untrusted headers.
            # The proxy may use HTTP to reach Gunicorn while the browser uses HTTPS.
            request.META["wsgi.url_scheme"] = "https"
        return self.get_response(request)


class PrivacyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            size = int(request.META.get("CONTENT_LENGTH") or "0")
        except ValueError:
            size = 2 * 1024 * 1024 + 1
        if size < 0 or size > 2 * 1024 * 1024:
            response = JsonResponse({"error": "Die Eingabe ist zu groß (maximal 2 MiB)."}, status=413)
        else:
            response = self.get_response(request)
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        response["Referrer-Policy"] = "no-referrer"
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        response["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self'; font-src 'self'; connect-src 'self'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        return response
