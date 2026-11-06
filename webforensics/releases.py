"""Read public GitHub releases only; never execute Git or Docker commands."""
import json
import re
import shlex
import ssl
import time
from http.client import HTTPException
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from . import __version__

REPOSITORY = "gl1tchb1rd/web_forensics"
API_URL = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
STABLE_TAG = re.compile(r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\+[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)?\Z")


class ReleaseError(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def version_number(tag):
    if not isinstance(tag, str) or len(tag) > 80:
        return None
    match = STABLE_TAG.fullmatch(tag)
    return tuple(int(part) for part in match.groups()) if match else None


def fetch_latest_release():
    # Fixed URL and headers. Incoming passwords, cookies and investigation data
    # are never forwarded. Inherited proxy configuration and TLS trust remain active.
    request = Request(API_URL, headers={
        "User-Agent": "WebForensics-ReleaseCheck",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Accept-Encoding": "identity",
    })
    try:
        opener = build_opener(NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))
        with opener.open(request, timeout=5) as response:
            if response.status != 200:
                raise ReleaseError("GitHub hat keine gültige Release-Antwort geliefert.")
            deadline = time.monotonic() + 12
            body = bytearray()
            while True:
                if time.monotonic() > deadline:
                    raise ReleaseError("Zeitlimit der GitHub-Abfrage erreicht. Bitte später erneut prüfen.")
                block = response.read1(min(16384, 262145 - len(body)))
                if not block:
                    break
                body.extend(block)
                if len(body) > 262144:
                    raise ReleaseError("Die GitHub-Antwort ist zu groß.")
            data = json.loads(body)
            if not isinstance(data, dict):
                raise ValueError
            return data
    except HTTPError as exc:
        status = exc.code
        remaining = exc.headers.get("X-RateLimit-Remaining") if exc.headers else None
        exc.close()
        if status == 404:
            return None
        if status == 429 or (status == 403 and remaining == "0"):
            raise ReleaseError("Das GitHub-Abfragelimit ist erreicht. Bitte später erneut prüfen.") from None
        raise ReleaseError("GitHub ist nicht erreichbar oder verweigert die Abfrage. Netzwerkfreigabe für api.github.com prüfen und später erneut versuchen.") from None
    except (URLError, OSError, HTTPException):
        raise ReleaseError("Die Release-Prüfung ist fehlgeschlagen. Netzwerkzugriff auf api.github.com und TLS-/Proxy-Konfiguration prüfen.") from None
    except (ValueError, UnicodeError):
        raise ReleaseError("Die GitHub-Antwort enthält keine gültigen Release-Daten.") from None


def check_latest_release():
    release = fetch_latest_release()
    result = {
        "installed_version": __version__,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "repository": REPOSITORY, "status": "no_release", "release": None,
        "instructions": [],
        "message": "Kein öffentlich abrufbarer, veröffentlichter regulärer Release gefunden. Entwürfe, Vorabversionen, einzelne Tags und main-Commits gelten nicht als Updates.",
    }
    if release is None:
        return result
    if not {"draft", "prerelease", "published_at", "tag_name"}.issubset(release):
        raise ReleaseError("Die GitHub-Antwort enthält keinen vollständigen Release-Datensatz.")
    if release.get("draft") is not False or release.get("prerelease") is not False or not release.get("published_at"):
        return result
    try:
        published = datetime.fromisoformat(release["published_at"].replace("Z", "+00:00"))
        if published.tzinfo is None:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise ReleaseError("Der Veröffentlichungszeitpunkt des Releases ist ungültig.") from None
    tag = release.get("tag_name")
    target = version_number(tag)
    installed = version_number(__version__)
    if target is None or installed is None:
        result.update(status="unsupported_version", message="Ein Release wurde gefunden, seine Versionsnummer kann aber nicht sicher verglichen werden. Unterstützt werden reguläre Tags wie v1.2.3 oder 1.2.3. Es werden keine Updatebefehle angeboten.")
        return result
    result["release"] = {"tag": tag, "published_at": published.isoformat(), "url": f"https://github.com/{REPOSITORY}/releases/tag/{quote(tag, safe='')}"}
    if target > installed:
        ref = shlex.quote("refs/tags/" + tag)
        fetch = shlex.quote(f"refs/tags/{tag}:refs/tags/{tag}")
        result.update(status="update_available", message=f"Der veröffentlichte Release {tag} ist neuer als die installierte Versionsnummer {__version__}.", instructions=[
            'test -z "$(git status --porcelain)"',
            f"git fetch --no-tags https://github.com/{REPOSITORY}.git {fetch}",
            f"git switch --detach {ref}",
            "docker compose up --build -d --force-recreate",
        ])
    elif target == installed:
        result.update(status="current", message=f"Kein neuerer Release verfügbar. Die installierte Versionsnummer entspricht {tag}.")
    else:
        result.update(status="ahead", message=f"Kein neuerer Release verfügbar. Deine installierte Versionsnummer liegt vor dem von GitHub als aktuell ausgewiesenen Release {tag}. Es wird kein Downgrade angeboten.")
    return result
