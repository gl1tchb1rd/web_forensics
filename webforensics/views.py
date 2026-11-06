import json

from django.core import signing
from django.http import HttpResponse, JsonResponse
from django.middleware.csrf import get_token
from django.middleware.csrf import (
    REASON_BAD_ORIGIN, REASON_CSRF_TOKEN_MISSING, REASON_NO_CSRF_COOKIE,
)
from urllib.parse import urlsplit
from django.shortcuts import render
from django.views.decorators.http import require_GET, require_POST
from django.conf import settings

from forensics.domain import OPTIONS, analyze_domain, make_plan
from forensics.headers import analyze_header
from forensics.network import NetworkError, network_budget, normalize_domain, resolver_description
from forensics.pdf import render_pdf
from forensics.report import filename, validate_case
from webforensics import __version__


def csrf_failure(request, reason=""):
    # Classify the failure without returning raw reasons (which may contain URLs)
    # or logging cookies, credentials, headers or investigation data.
    code = "csrf_failed"
    message = "Die Sicherheitsprüfung ist fehlgeschlagen. Bitte die Seite vollständig neu laden und die Cookie-/Proxy-Konfiguration prüfen."
    if reason.startswith(REASON_BAD_ORIGIN.split("%s", 1)[0]):
        origin = request.headers.get("Origin", "")
        try:
            http_origin = urlsplit(origin).scheme.lower() == "http"
        except ValueError:
            http_origin = False
        if settings.PUBLIC_HTTPS and http_origin:
            code = "csrf_https_mismatch"
            message = "Die Anwendung ist auf HTTPS eingestellt, die Browseranfrage verwendet jedoch HTTP. Bitte über HTTPS zugreifen oder für einen reinen HTTP-/SSH-Tunnel-Test WF_HTTPS=0 setzen und den Container neu erstellen."
        else:
            code = "csrf_origin_mismatch"
            message = "Die Browseradresse passt nicht zur Herkunftsprüfung. Bei HTTPS hinter einem Reverse-Proxy WF_HTTPS=1 setzen und den öffentlichen Host-Header erhalten. WF_TRUSTED_ORIGINS muss bei einer abweichenden Proxy-Adresse die vollständige öffentliche Adresse mit Protokoll und gegebenenfalls Port enthalten. Container nach Änderungen neu erstellen."
    elif reason == REASON_NO_CSRF_COOKIE or reason.startswith("CSRF cookie "):
        code = "csrf_cookie_missing"
        message = "Das Sicherheitscookie fehlt oder ist ungültig. Bitte Cookies für diese Website zulassen und die Seite vollständig neu laden. Bei HTTP-Zugriff muss WF_HTTPS=0 gesetzt sein; bei HTTPS WF_HTTPS=1. Den Container nach Konfigurationsänderungen neu erstellen."
    elif reason == REASON_CSRF_TOKEN_MISSING:
        code = "csrf_token_missing"
        message = "Der Sicherheitstoken der Seite fehlt. Bitte die Seite vollständig neu laden. Der Reverse-Proxy muss den X-CSRFToken-Header durchreichen."
    elif reason.startswith("CSRF token "):
        code = "csrf_token_invalid"
        message = "Der Sicherheitstoken der Seite passt nicht zum Cookie. Bitte die Seite vollständig neu laden; gegebenenfalls weitere alte Tabs dieser Anwendung schließen."
    elif reason.startswith("Referer checking failed"):
        code = "csrf_referer_invalid"
        message = "Die Herkunftsangabe der HTTPS-Anfrage fehlt oder passt nicht. Bitte die Anwendung über ihre öffentliche Browseradresse öffnen und die Host-/Herkunftskonfiguration des Reverse-Proxys prüfen."
    return JsonResponse({"error": message, "code": code}, status=403)


def read_json(request):
    if request.content_type != "application/json":
        raise ValueError("Die Anfrage muss JSON enthalten.")
    try:
        data = json.loads(request.body)
    except (ValueError, UnicodeError):
        raise ValueError("Ungültige Anfrage.") from None
    if not isinstance(data, dict):
        raise ValueError("Ungültige Anfrage.")
    return data


@require_GET
def index(request):
    return render(request, "index.html", {"csrf_token_value": get_token(request), "version": __version__, "resolver": resolver_description(), "has_logo": (settings.BASE_DIR / "static/brand/logo.png").is_file()})


@require_GET
def health(request):
    return JsonResponse({"status": "ok", "version": __version__})


@require_POST
def plan(request):
    try:
        data = read_json(request)
        module = data.get("module")
        if module not in ("domain", "headers"):
            raise ValueError("Unbekanntes Modul.")
        supplied = data.get("options", {})
        if not isinstance(supplied, dict) or any(not isinstance(v, bool) for v in supplied.values()):
            raise ValueError("Ungültige Abfrageoptionen.")
        options = {k: bool(supplied.get(k)) for k in OPTIONS}
        if module == "headers":
            options = {"network": True}
        with network_budget(40):
            result = make_plan(module, data.get("domain", ""), options)
        return JsonResponse({"plan": result, "token": signing.dumps(result, salt="query-plan", compress=True)})
    except ValueError as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    except Exception:
        return JsonResponse({"error": "Der Abfrageplan konnte nicht erstellt werden. Bitte die Serverkonfiguration prüfen."}, status=503)


@require_POST
def analyze(request):
    try:
        data = read_json(request)
        case = validate_case(data.get("case"))
        module = data.get("module")
        original = data.get("input")
        if not isinstance(original, str):
            raise ValueError("Bitte eine Eingabe angeben.")
        enrich = data.get("enrich") is True
        query_plan = None
        if module == "domain" or (module == "headers" and enrich):
            if data.get("consent") is not True:
                raise ValueError("Bitte die angezeigten externen Abfragen ausdrücklich bestätigen.")
            query_plan = signing.loads(data.get("plan_token", ""), salt="query-plan", max_age=600)
            if query_plan["module"] != module or (module == "domain" and normalize_domain(original) != query_plan["domain"]):
                raise ValueError("Die Eingabe hat sich geändert. Bitte den Abfrageplan neu erstellen.")
        if module == "domain":
            with network_budget(65):
                report = analyze_domain(case, original, query_plan)
        elif module == "headers":
            with network_budget(65):
                report = analyze_header(case, original, enrich=enrich, plan=query_plan)
        else:
            raise ValueError("Unbekanntes Modul.")
        return JsonResponse({"report": report, "token": signing.dumps(report, salt="pdf-report", compress=True), "filename": filename(report)})
    except signing.BadSignature:
        return JsonResponse({"error": "Der Abfrageplan ist ungültig oder abgelaufen. Bitte erneut erstellen."}, status=400)
    except NetworkError as exc:
        return JsonResponse({"error": str(exc)}, status=503)
    except ValueError as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    except Exception:
        return JsonResponse({"error": "Die Analyse konnte nicht abgeschlossen werden. Es wurden keine Ergebnisse gespeichert."}, status=500)


@require_POST
def download_pdf(request):
    try:
        data = read_json(request)
        token = data.get("token")
        if not isinstance(token, str) or len(token) > 1800000:
            raise ValueError("Ungültige Berichtsdaten.")
        report = signing.loads(token, salt="pdf-report", max_age=1800)
        result = render_pdf(report)
        response = HttpResponse(result, content_type="application/pdf")
        response["Content-Disposition"] = f'attachment; filename="{filename(report)}"'
        return response
    except signing.BadSignature:
        return JsonResponse({"error": "Der Bericht ist abgelaufen oder die Anwendung wurde neu gestartet. Bitte die Analyse erneut durchführen."}, status=400)
    except ValueError as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    except Exception:
        return JsonResponse({"error": "Das PDF konnte nicht erzeugt werden. Es wurde kein Bericht auf dem Server gespeichert."}, status=500)
