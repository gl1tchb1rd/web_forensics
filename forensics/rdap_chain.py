"""Bounded domain-RDAP registry/registrar traversal, with per-response evidence."""
import hashlib
import json
import re
import ipaddress
from datetime import datetime, timezone
from urllib.parse import unquote, urljoin, urlsplit

from .network import NetworkError, is_public, normalize_domain, remaining


def domain_url(value, domain):
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.port not in (None, 443)
                or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment
                or any(ord(c) < 33 for c in value)):
            raise ValueError
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            normalize_domain(parsed.hostname)
        else:
            if not is_public(address):
                raise ValueError
        path = unquote(parsed.path).rstrip("/")
        match = re.search(r"/domain/([^/]+)$", path, re.I)
        if not match or normalize_domain(match[1]) != domain:
            raise ValueError
        return value
    except (ValueError, UnicodeError):
        raise NetworkError("RDAP-Verweis ist keine reine HTTPS-Domainabfrage auf Port 443 für dieselbe Registrierungsdomain.") from None


def walk_domain_rdap(url, domain, allowed_hosts, fetch, max_requests=8):
    domain = normalize_domain(domain)
    steps, problems, skipped = [], [], []
    queue = [(url, "")]
    visited = set()
    initial_host = urlsplit(url).hostname
    if initial_host not in allowed_hosts:
        raise NetworkError("Der erste RDAP-Dienst ist nicht im bestätigten Abfrageplan enthalten.")
    while queue and len(steps) < max_requests:
        try:
            remaining(1)
        except NetworkError as exc:
            problems.append(str(exc))
            break
        current, parent = queue.pop(0)
        if current in visited:
            skipped.append(current)
            continue
        visited.add(current)
        rec = {"url": current, "parent": parent, "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "status": None, "data": None, "raw": "", "sha256": "", "bytes": 0, "error": "", "links": []}
        steps.append(rec)
        try:
            domain_url(current, domain)
            status, headers, body = fetch(current, limit=128 * 1024)
            rec.update(status=status, raw=body.decode("utf-8", "replace"), bytes=len(body), sha256=hashlib.sha256(body).hexdigest())
            targets = []
            if status in (301, 302, 303, 307, 308):
                location = next((v for k, v in headers.items() if k.lower() == "location"), "")
                if not location:
                    raise NetworkError("RDAP-Weiterleitung ohne Ziel.")
                targets.append(urljoin(current, location))
            elif status == 200:
                data = json.loads(body)
                if not isinstance(data, dict):
                    raise ValueError
                if normalize_domain(data.get("ldhName", "")) != domain:
                    raise NetworkError("Die RDAP-Antwort bestätigt nicht die abgefragte Registrierungsdomain; weitere Verweise werden nicht verfolgt.")
                rec["data"] = data
                for link in data.get("links", []):
                    if not isinstance(link, dict):
                        continue
                    relation = str(link.get("rel", "")).lower()
                    content_type = str(link.get("type", "")).lower().split(";", 1)[0].strip()
                    if relation == "related" and content_type in ("application/rdap+json", "application/json"):
                        href = link.get("href")
                        if not isinstance(href, str):
                            raise NetworkError("RDAP-Weiterverweis ohne gültige Adresse.")
                        targets.append(urljoin(current, href))
            else:
                raise NetworkError(f"RDAP-Dienst antwortet mit HTTP {status}; frühere Ergebnisse bleiben erhalten.")
            for target in targets:
                try:
                    domain_url(target, domain)
                except NetworkError as exc:
                    # Entity/contact references are not registration-chain endpoints.
                    # Never send their URLs (possibly containing contact data) onward.
                    problems.append(str(exc))
                    rec["error"] = str(exc)
                    continue
                rec["links"].append(target)
                if target in visited or any(queued == target for queued, _ in queue):
                    skipped.append(target)
                else:
                    queue.append((target, current))
        except NetworkError as exc:
            rec["error"] = str(exc)
            problems.append(str(exc))
        except (ValueError, TypeError, KeyError, AttributeError):
            rec["error"] = "Ungültige oder nicht domainbezogene RDAP-Antwort."
            problems.append(rec["error"])
    if queue and len(steps) >= max_requests:
        problems.append(f"RDAP-Limit von {max_requests} Abfragen erreicht; die Kette ist nicht vollständig.")
    return {"steps": steps, "complete": not problems and not queue, "pending": [target for target, _ in queue],
            "skipped": skipped, "reason": " ".join(dict.fromkeys(problems)) if problems else "Alle neuen domainbezogenen HTTPS-Verweise abgearbeitet; kein weiterer neuer Dienst benannt."}
