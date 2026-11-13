# Copyright (C) 2026 Forensic SiteSaver contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Adapted from forensic_sitesaver/domain_analysis.py at c27b021a2500bbc7a499e4791129f536c3ee94c7.

Retains its IANA fallback, VeriSign query variants and breadth-first referral
traversal. Adds public-IP pinning, protocol validation, budgets and report traces.
No input or reply is written to a file or application log.
"""
import hashlib
import ipaddress
import re
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .network import NetworkError, is_public, normalize_domain, open_whois, remaining
from .report import section

MAX_SERVERS = 8  # Additional servers after IANA, not an ordinary end condition.
MAX_RESPONSE = 128 * 1024
RAW_EXCERPT = 16384
LABELS = {"refer", "whois", "whois server", "registrar whois server", "registry whois server", "referralserver", "referral server"}
DENIAL = re.compile(r"(?im)^\s*(?:%\s*)?(?:error\s*:?\s*\d*\s*:?\s*)?(?:access denied|too many (?:queries|requests)|(?:whois |query |rate )?limit exceeded|rate limit exceeded|you have exceeded|(?:this |the )?whois (?:service|server).*(?:discontinued|no longer|unavailable)|service unavailable|request.*rate.limit)")
NO_MATCH = re.compile(r"(?im)^\s*(?:%\s*)?(?:no match(?:ing)?\b|not found\b|no (?:entries|objects|data) found\b)")


def server_name(value):
    parts = value.strip().split()
    value = parts[0].strip("<>(){},;") if parts else ""
    if not value:
        raise ValueError("Leerer WHOIS-Verweis.")
    if "://" not in value:
        value = "whois://" + value
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() != "whois":
            raise ValueError("Verweis verwendet kein WHOIS-Protokoll (TCP 43), z. B. RWHOIS oder eine Webadresse.")
        if parsed.port not in (None, 43) or parsed.username is not None or parsed.password is not None or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError("WHOIS-Verweis enthält einen unerlaubten Port, Pfad oder Anmeldedaten.")
        host = (parsed.hostname or "").rstrip(".").lower()
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return normalize_domain(host)
        if not is_public(address):
            raise ValueError("Nicht öffentliche WHOIS-Adresse gesperrt.")
        return str(address)
    except (UnicodeError, ValueError) as exc:
        raise ValueError(str(exc) or "Ungültiger WHOIS-Verweis.") from None


def referrals(text):
    found, rejected = [], []
    for line in text.splitlines():
        if ":" not in line:
            continue
        label, value = line.strip().split(":", 1)
        if re.sub(r"[ \t]+", " ", label.strip().lower()) not in LABELS or not value.strip():
            continue
        try:
            host = server_name(value)
            if host not in found:
                found.append(host)
        except ValueError as exc:
            reason = str(exc)
            if reason not in rejected:
                rejected.append(reason)
    return found, rejected


def query_candidates(server, domain):
    if server in {"whois.verisign-grs.com", "whois.crsnic.net"}:
        return [f"dom {domain}", f"domain {domain}", f"={domain}", domain]
    return [domain]


def looks_like_domain(text, domain):
    low = text.lower()
    for match in re.finditer(r"(?im)^\s*domain(?:\s+name)?\s*:\s*(\S+)", text):
        try:
            if normalize_domain(match[1]) == domain:
                return True
        except ValueError:
            continue
    return "registry domain id:" in low or "registrar whois server:" in low


def whois_fields(text):
    labels = {
        "domain name": "Domainname", "domain": "Domainname", "registry domain id": "Registry-Domain-ID",
        "registrar": "Registrar", "registrar-name": "Registrar", "registrar name": "Registrar",
        "registrar iana id": "Registrar-IANA-ID", "registrar url": "Registrar-URL",
        "creation date": "Registrierungsdatum", "created": "Registrierungsdatum",
        "updated date": "Änderungsdatum", "last modified": "Änderungsdatum", "changed": "Änderungsdatum",
        "registry expiry date": "Ablaufdatum", "registrar registration expiration date": "Ablaufdatum",
        "expiry date": "Ablaufdatum", "domain status": "Domainstatus", "status": "Domainstatus",
        "name server": "Nameserver", "nserver": "Nameserver", "dnssec": "DNSSEC-Angabe",
        "registrar abuse contact email": "Registrar / Missbrauchskontakt / E-Mail",
        "registrar abuse contact phone": "Registrar / Missbrauchskontakt / Telefon",
        "owner": "Domaininhaber", "holder": "Domaininhaber", "registrant": "Domaininhaber",
        "org-name": "Organisation", "organization": "Organisation", "organisation": "Organisation",
    }
    contacts = {
        "name": "Name", "organization": "Organisation", "organisation": "Organisation",
        "street": "Straße", "street1": "Straße 1", "street2": "Straße 2", "street3": "Straße 3",
        "city": "Ort", "state/province": "Bundesland / Region", "state": "Bundesland / Region",
        "postal code": "Postleitzahl", "country": "Land", "phone": "Telefon", "phone ext": "Telefon-Durchwahl",
        "fax": "Fax", "fax ext": "Fax-Durchwahl", "email": "E-Mail",
    }
    for prefix, role in (("registrant", "Domaininhaber"), ("admin", "Administrativer Kontakt"), ("tech", "Technischer Kontakt"), ("billing", "Rechnungskontakt")):
        for name, label in contacts.items():
            labels[prefix + " " + name] = role + " / " + label
            labels[prefix + " contact " + name] = role + " / " + label
    rows = []
    for line in text.splitlines():
        if ":" not in line:
            if re.search(r"redacted for privacy|data redacted|not disclosed|not publicly accessible", line, re.I):
                row = ["Datenschutzhinweis (laut WHOIS)", line.strip()[:2048]]
                if row not in rows:
                    rows.append(row)
            continue
        label, value = line.strip().split(":", 1)
        normalized = re.sub(r"[ \t]+", " ", label.lower().strip())
        if normalized in labels and value.strip():
            value = value.strip()
            row = [labels[normalized] + " (laut WHOIS)", value[:2048] + (" … [gekürzt]" if len(value) > 2048 else "")]
            if row not in rows:
                rows.append(row)
    # Do not let long nameserver/status lists hide holder/contact fields later
    # in the reply. The complete response remains available in raw data.
    contact_rows = [row for row in rows if any(role in row[0] for role in ("Domaininhaber", "Kontakt", "Datenschutzhinweis"))]
    others = [row for row in rows if row not in contact_rows]
    return (contact_rows + others)[:96]


def whois_query(server, query):
    result = {"server": server, "query": query, "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "ok": False, "complete": False, "text": "", "error": "", "sha256": "", "bytes": 0, "encoding": "", "referrals_found": [], "rejected": []}
    body = bytearray()
    try:
        server = server_name(server)
        if not query or len(query) > 512 or not re.fullmatch(r"[a-zA-Z0-9. =-]+", query):
            raise NetworkError("Ungültige WHOIS-Abfrage; Steuerzeichen und Mehrfachabfragen sind gesperrt.")
        deadline = time.monotonic() + 8
        with open_whois(server) as sock:
            sock.sendall((query + "\r\n").encode("ascii"))
            while True:
                left = min(deadline - time.monotonic(), remaining(5))
                if left <= 0:
                    raise NetworkError("Zeitlimit während der WHOIS-Antwort erreicht.")
                sock.settimeout(left)
                block = sock.recv(min(16384, MAX_RESPONSE + 1 - len(body)))
                if not block:
                    result["complete"] = True
                    break
                body.extend(block)
                if len(body) > MAX_RESPONSE:
                    raise NetworkError("WHOIS-Antwortgrößenlimit erreicht; nur eine Teilantwort empfangen.")
        if not body:
            result["error"] = "Der WHOIS-Dienst hat eine leere Antwort geliefert."
        else:
            result["ok"] = True
    except socket.timeout:
        result["error"] = "Zeitlimit beim WHOIS-Abruf erreicht; empfangene Daten sind eine Teilantwort."
    except (NetworkError, ValueError) as exc:
        result["error"] = str(exc)
    except OSError:
        result["error"] = "WHOIS-Verbindung fehlgeschlagen; empfangene Daten können unvollständig sein."
    result["bytes"] = len(body)
    if body:
        result["sha256"] = hashlib.sha256(body).hexdigest()
        try:
            result["text"] = body.decode("utf-8")
            result["encoding"] = "UTF-8"
        except UnicodeDecodeError:
            result["text"] = body.decode("latin-1")
            result["encoding"] = "ISO-8859-1 (Fallback; WHOIS legt die Kodierung nicht verbindlich fest)"
    return result


def whois_bundle(domain, max_referral_servers=MAX_SERVERS):
    domain = normalize_domain(domain)
    attempts, queue, queued = [], [], set()
    seen = {"whois.iana.org"}
    queried = ["whois.iana.org"]
    skipped, problems = [], []

    def attempt(server, query, stage, parent):
        rec = whois_query(server, query)
        rec.update(stage=stage, referred_by=parent)
        rec["referrals_found"], rec["rejected"] = referrals(rec["text"])
        if DENIAL.search(rec["text"]) and not rec["error"]:
            rec["error"] = "Der WHOIS-Dienst verweigert die Abfrage, ist nicht mehr verfügbar oder meldet ein Abfragelimit."
        attempts.append(rec)
        return rec

    def enqueue(host, stage, parent):
        if host in seen or host in queued:
            item = f"{parent} → {host}: bereits abgefragt oder vorgemerkt; keine erneute Verbindung."
            if item not in skipped:
                skipped.append(item)
            return
        queued.add(host)
        queue.append((host, stage, parent))

    initial = attempt("whois.iana.org", domain, "IANA", "")
    roots = [host for host in initial["referrals_found"] if host != "whois.iana.org"]
    if not roots:
        initial = attempt("whois.iana.org", domain.rsplit(".", 1)[-1], "IANA / TLD-Fallback", "")
        roots = [host for host in initial["referrals_found"] if host != "whois.iana.org"]
    for host in roots:
        enqueue(host, "Registry", "whois.iana.org")
    if not roots:
        problems.append("IANA liefert auch nach dem TLD-Fallback keinen nutzbaren weiterführenden WHOIS-Server.")
    if initial["error"] or initial["rejected"]:
        problems.append("Die abschließende IANA-Antwort ist unvollständig oder enthält nicht unterstützte Verweise.")

    followed = 0
    while queue and followed < max_referral_servers:
        try:
            remaining(1)
        except NetworkError:
            problems.append("Gesamtzeitlimit erreicht; vorgemerkte WHOIS-Server wurden nicht mehr abgefragt.")
            break
        host, stage, parent = queue.pop(0)
        queued.discard(host)
        seen.add(host)
        queried.append(host)
        followed += 1
        # Preserve referrals from EVERY query variant, including non-domain replies.
        collected = []
        final = None
        for query in query_candidates(host, domain):
            final = attempt(host, query, stage, parent)
            collected.extend(target for target in final["referrals_found"] if target not in collected)
            if final["error"] or looks_like_domain(final["text"], domain):
                break
        if final and (final["error"] or not final["complete"] or not final["text"]):
            problems.append(f"WHOIS-Antwort von {host} fehlt oder ist unvollständig.")
        elif final and not collected and not looks_like_domain(final["text"], domain) and not NO_MATCH.search(final["text"]):
            problems.append(f"{host} liefert weder einen erkennbaren Domain-Datensatz noch einen weiterführenden WHOIS-Verweis; das Kettenende ist nicht bestätigt.")
        for rec in attempts:
            if rec["server"] == host and rec["rejected"]:
                problems.append(f"{host}: nicht unterstützter oder gesperrter Weiterverweis.")
                break
        for target in collected:
            enqueue(target, "Registrar" if stage == "Registry" else f"Weiterverweis {followed + 1}", host)
    limited = bool(queue) and followed >= max_referral_servers
    if limited:
        problems.append(f"Sicherheitslimit von {max_referral_servers} weiteren WHOIS-Servern erreicht; die Kette ist nicht vollständig abgearbeitet.")
    complete = not problems
    reason = "Alle neu benannten unterstützten WHOIS-Server abgefragt; kein weiterer neuer Verweis vorhanden."
    if domain.endswith(".de") and queried == ["whois.iana.org", "whois.denic.de"] and complete:
        reason += " Bei .de endet die klassische WHOIS-Kette regulär bei DENIC; daraus folgt kein fehlender Registrar."
    return {"query": domain, "attempts": attempts, "queried_servers": queried,
            "complete": complete, "reason": reason if complete else " ".join(dict.fromkeys(problems)),
            "pending": [item[0] for item in queue], "skipped": skipped,
            "referral_limit_reached": limited, "referral_limit": max_referral_servers}


def add_whois(report, domain):
    bundle = whois_bundle(domain)
    rows = [["Registrierungsdomain", domain], ["Abgefragte Dienste (Reihenfolge)", "\n".join(bundle["queried_servers"])],
            ["Ende / Abbruch", bundle["reason"]], ["Offene Dienste", ", ".join(bundle["pending"]) or "Keine"]]
    edges = list(dict.fromkeys(f"{rec['referred_by']} → {rec['server']}" for rec in bundle["attempts"] if rec["referred_by"]))
    if edges:
        rows.append(["Verfolgte Weiterverweise", "\n".join(edges)])
    rows.extend(["Doppelter Verweis", text] for text in bundle["skipped"][:16])
    section(report, "WHOIS-Abfragekette", rows, status="ok" if bundle["complete"] else "unavailable",
            note="Reihenfolge der Abfragen, bei mehreren Verweisen als Warteschlange. Das Kettenende bestätigt keine Vollständigkeit oder Richtigkeit der veröffentlichten Registrierungsdaten.")
    for number, rec in enumerate(bundle["attempts"], 1):
        host = "[" + rec["server"] + "]" if ":" in rec["server"] else rec["server"]
        source = f"whois://{host}:43"
        rows = [["Stufe", rec["stage"]], ["Abfrage", rec["query"]], ["Abfragezeitpunkt (UTC)", rec["captured_at"]],
                ["Verweis von", rec["referred_by"] or "Start bei IANA"], ["Weitere Dienste", ", ".join(rec["referrals_found"]) or "Keine"],
                ["Empfangene Bytes", str(rec["bytes"])], ["Kodierung", rec["encoding"] or "Keine Daten"],
                ["SHA-256 der empfangenen Bytes", rec["sha256"] or "Keine Daten"]]
        rows.extend(whois_fields(rec["text"]))
        notes = ["WHOIS über TCP 43 ist unverschlüsselt. Antworten können beschränkt, veraltet oder manipuliert sein."]
        notes.append("Strukturierte Anzeige einschließlich Inhaber- und Kontaktfeldern: maximal 96 Werte mit je 2.048 Zeichen; Datumsangaben unverändert aus der Quelle, ohne angenommene Zeitzone.")
        if rec["error"]:
            notes.append(rec["error"])
        if not rec["complete"]:
            notes.append("Teilantwort: Eine Prüfsumme bezieht sich ausschließlich auf die tatsächlich empfangenen Bytes." if rec["bytes"] else "Keine Antwortbytes empfangen.")
        if len(rec["text"]) > RAW_EXCERPT:
            notes.append(f"Rohdaten-Auszug auf {RAW_EXCERPT} Zeichen begrenzt. Die Prüfsumme bezieht sich auf alle empfangenen Bytes.")
        notes.extend(rec["rejected"])
        section(report, f"WHOIS {number}: {rec['server']}", rows,
                status="ok" if rec["ok"] and rec["complete"] and not rec["error"] else "unavailable",
                note=" ".join(notes), raw=rec["text"][:RAW_EXCERPT], source=source)
        if source not in report["sources"]:
            report["sources"].append(source)
    report["summary"].append({"level": "info" if bundle["complete"] else "notice",
                              "text": f"WHOIS-Kette: {len(bundle['queried_servers'])} Dienst(e), {len(bundle['attempts'])} Abfrage(n). {bundle['reason']}"})
    for rec in reversed(bundle["attempts"]):
        names = list(dict.fromkeys(value for label, value in whois_fields(rec["text"])
                                  if label in ("Domaininhaber (laut WHOIS)", "Domaininhaber / Name (laut WHOIS)", "Domaininhaber / Organisation (laut WHOIS)")))
        if names:
            report["summary"].append({"level": "info", "text": f"WHOIS-Inhaberangaben von {rec['server']}: " + " / ".join(names) + "."})
            break
    return bundle
