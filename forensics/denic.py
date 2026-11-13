# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Public DENIC WebWhois, adapted from the supplied domain_analysis.py.

Retains its query parameter and labelled holder/member sections. Responses stay
in memory; HTTPS targets, redirects, response size and total time remain bounded.
"""
import hashlib
import re
from datetime import datetime, timezone
from http.cookiejar import CookieJar
from urllib.parse import parse_qs, quote, urljoin, urlsplit

from bs4 import BeautifulSoup

from .network import NetworkError, fetch_https, normalize_domain, remaining
from .report import section

HOST = "webwhois.denic.de"
BASE_URL = f"https://{HOST}/"
CONTACT_LABELS = {
    "name": "name", "organisation": "organization", "organization": "organization",
    "adresse": "address", "anschrift": "address", "postleitzahl": "postal_code",
    "ort": "city", "land": "country", "e-mail": "email", "email": "email", "telefon": "phone",
}
DISPLAY_LABELS = {
    "name": "Name", "organization": "Organisation", "address": "Anschrift",
    "postal_code": "Postleitzahl", "city": "Ort", "country": "Land", "email": "E-Mail", "phone": "Telefon",
}


def text_lines(html):
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    return [re.sub(r"\s+", " ", text).strip() for text in soup.stripped_strings if text.strip()]


def section_lines(lines, start, ends):
    for index, line in enumerate(lines):
        if line.casefold().rstrip(":") == start.casefold():
            stop = next((n for n in range(index + 1, len(lines)) if lines[n].casefold().rstrip(":") in {end.casefold() for end in ends}), len(lines))
            return lines[index + 1:stop]
    return []


def contact_fields(lines):
    fields, current, values = {}, None, []

    def save():
        if current and values:
            fields[current] = "\n".join(values)[:4096]

    for line in lines:
        label, separator, inline = line.partition(":")
        key = CONTACT_LABELS.get(label.strip().casefold())
        if key:
            save()
            current, values = key, [inline.strip()] if separator and inline.strip() else []
        elif current:
            values.append(line)
    save()
    return fields


def find_date(lines, label):
    for index, line in enumerate(lines):
        if label.casefold() in line.casefold():
            for value in lines[index:index + 6]:
                match = re.search(r"\b\d{2}\.\d{2}\.\d{4}\b", value)
                if match:
                    return match[0]
    return None


def parse_denic_webwhois(html, domain):
    lines = text_lines(html)
    joined = " ".join(lines).casefold()
    state = "free" if "ist frei" in joined or "available for registration" in joined else "registered" if "ist bereits registriert" in joined or "is already registered" in joined else "unknown"
    # A returned, explicitly labelled different domain must never be attributed
    # to the requested one. A query form's input value is not a result label.
    for index, line in enumerate(lines):
        label, separator, inline = line.partition(":")
        if label.casefold().strip() in ("domain", "domainname"):
            candidate = inline.strip() if separator else (lines[index + 1] if index + 1 < len(lines) else "")
            try:
                returned_domain = normalize_domain(candidate)
            except ValueError:
                continue
            if returned_domain != domain:
                raise NetworkError("Die DENIC-Seite nennt eine andere Domain als die angefragte Registrierungsdomain.")
    member = contact_fields(section_lines(lines, "Informationen zur Domainverwaltung", ("Technische Daten", "Informationen zum Domaininhaber")))
    holder_lines = section_lines(lines, "Informationen zum Domaininhaber", ("Hinweis für Domaininhaber", "Hinweis für Dritte", "Informationen zur Domainverwaltung", "Technische Daten"))
    holder_text = " ".join(holder_lines).casefold()
    if "nicht öffentlich zugänglich" in holder_text or "not publicly accessible" in holder_text:
        holder = {"visibility": "not_public"}
    else:
        fields = contact_fields(holder_lines)
        holder = {"visibility": "public" if fields else "unknown", **fields}
    registration = find_date(lines, "Datum der letzten Registrierung")
    updated = find_date(lines, "Letzte Aktualisierung")
    return {"domain": domain, "registration_state": state, "registration_date": registration,
            "last_update": updated, "managing_denic_member": member or None, "domain_holder": holder,
            "recognized": bool(state != "unknown" or member or holder["visibility"] != "unknown" or registration or updated)}


def valid_target(url, domain):
    try:
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or parsed.hostname != HOST or parsed.port not in (None, 443)
                or parsed.username is not None or parsed.password is not None or parsed.fragment
                or any(ord(c) < 33 for c in url)):
            raise ValueError
        for value in parse_qs(parsed.query).get("query", []):
            if normalize_domain(value) != domain:
                raise ValueError
    except (ValueError, UnicodeError):
        raise NetworkError("DENIC-Weiterleitung außerhalb der freigegebenen HTTPS-Inhaberauskunft gestoppt.") from None


def add_denic_webwhois(report, domain):
    domain = normalize_domain(domain)
    if not domain.endswith(".de"):
        raise ValueError("Die DENIC-Web-WHOIS-Abfrage ist nur für .de-Domains vorgesehen.")
    url = BASE_URL + "?lang=de&query=" + quote(domain)
    captured = datetime.now(timezone.utc).isoformat(timespec="seconds")
    rows = [["Registrierungsdomain", domain], ["Abfragezeitpunkt (UTC)", captured]]
    raw, body, status, last_requested = "", b"", None, url
    # Like the original requests.Session, preserve service-issued cookies only
    # within this one lookup and its validated same-service redirects.
    cookies = CookieJar()
    try:
        for _ in range(4):
            valid_target(url, domain)
            remaining(1)
            last_requested = url
            if url not in report["sources"]:
                report["sources"].append(url)
            raw, body, status = "", b"", None
            status, headers, body = fetch_https(url, limit=1024 * 1024, accept="text/html,application/xhtml+xml;q=0.9,*/*;q=0.8", cookie_jar=cookies)
            if status in (301, 302, 303, 307, 308):
                location = next((v for k, v in headers.items() if k.lower() == "location"), "")
                if not location:
                    raise NetworkError("DENIC-Weiterleitung ohne Ziel.")
                url = urljoin(url, location)
                continue
            break
        else:
            raise NetworkError("Zu viele DENIC-Weiterleitungen.")
        content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
        charset = re.search(r"charset\s*=\s*['\"]?([\w-]+)", content_type, re.I)
        try:
            raw = body.decode(charset[1] if charset else "utf-8")
        except (LookupError, UnicodeError):
            raw = body.decode("utf-8", "replace")
        if status != 200:
            raise NetworkError(f"DENIC-Web-WHOIS antwortet mit HTTP {status}.")
        if content_type and not any(kind in content_type.lower() for kind in ("text/html", "application/xhtml+xml")):
            raise NetworkError("Die DENIC-Antwort ist keine HTML-Domainauskunft.")
        parsed = parse_denic_webwhois(raw, domain)
        if not parsed["recognized"]:
            raise NetworkError("Keine auswertbare DENIC-Domainauskunft in der Antwort erkannt (z. B. Startseite, Zugriffsschutz oder geändertes Seitenformat).")
        state = parsed["registration_state"]
        rows.append(["Domainstatus", {"registered": "Bereits registriert", "free": "Laut DENIC verfügbar", "unknown": "Kein eindeutiger Status angegeben"}[state]])
        for key, label in (("registration_date", "Datum der letzten Registrierung"), ("last_update", "Letzte Aktualisierung")):
            if parsed[key]:
                rows.append([label, parsed[key]])
        for key, prefix in (("domain_holder", "Domaininhaber"), ("managing_denic_member", "Verwaltendes DENIC-Mitglied")):
            contact = parsed[key] or {}
            for field, label in DISPLAY_LABELS.items():
                if contact.get(field):
                    rows.append([prefix + " / " + label, contact[field]])
        if parsed["domain_holder"]["visibility"] == "not_public":
            rows.append(["Domaininhaber", "DENIC kennzeichnet die Inhaberdaten ausdrücklich als nicht öffentlich zugänglich."])
        elif parsed["domain_holder"]["visibility"] == "unknown" and state != "free":
            rows.append(["Domaininhaber", "Keine auswertbaren Inhaberangaben in dieser Antwort; daraus wird kein Datenschutzstatus abgeleitet."])
        rows.extend([["HTTP-Status", str(status)], ["SHA-256 der HTML-Antwortbytes", hashlib.sha256(body).hexdigest()]])
        section(report, "DENIC-Web-WHOIS / Inhaberauskunft", rows, status="empty" if state == "free" else "ok", raw=raw, source=url,
                note="Öffentliche DENIC-Domainabfrage. Das verwaltende DENIC-Mitglied kann bei Reseller-Verträgen vom direkten Anbieter abweichen. Datumsangaben werden unverändert aus der Quelle übernommen.")
        holder = parsed["domain_holder"]
        names = list(dict.fromkeys(" ".join(holder[key].split()) for key in ("name", "organization") if holder.get(key)))
        if names:
            report["summary"].append({"level": "info", "text": "DENIC-Web-WHOIS / öffentlicher Domaininhaber: " + " / ".join(names) + "."})
        member = parsed["managing_denic_member"] or {}
        if member.get("name"):
            report["summary"].append({"level": "info", "text": "Verwaltendes DENIC-Mitglied: " + " ".join(member["name"].split()) + "."})
        return parsed
    except NetworkError as exc:
        if status is not None:
            rows.append(["HTTP-Status", str(status)])
        if body:
            rows.append(["SHA-256 der empfangenen Antwortbytes", hashlib.sha256(body).hexdigest()])
        section(report, "DENIC-Web-WHOIS / Inhaberauskunft", rows, status="unavailable", note=str(exc), raw=raw, source=last_requested)
        return None
