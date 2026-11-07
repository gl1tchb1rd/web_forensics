import csv
import hashlib
import io
import ipaddress
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from functools import lru_cache
from urllib.parse import quote, urljoin, urlsplit

import dns.exception
import dns.resolver
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .network import NetworkError, fetch_https, is_public, normalize_domain, open_tls, resolver, resolver_description
from .report import finish, new_report, section
from .registration import registration_domain
from .whois import add_whois
from .rdap_chain import walk_domain_rdap

OPTIONS = ("rdap", "whois", "network", "tls", "http")
REGISTRAR_DIRECTORY = "https://www.iana.org/assignments/registrar-ids/registrar-ids-1.csv"
# DENIC documents this service separately; .de is absent from the DNS bootstrap.
# https://www.denic.de/services/whois-service/rdap-service/
DOMAIN_RDAP_SERVICES = {"de": "https://rdap.denic.de/"}


@lru_cache(maxsize=3)
def bootstrap(kind):
    url = f"https://data.iana.org/rdap/{kind}.json"
    status, _, body = fetch_https(url)
    if status != 200:
        raise NetworkError(f"IANA-RDAP-Verzeichnis nicht verfügbar (HTTP {status}).")
    try:
        data = json.loads(body)
        return data["services"]
    except (ValueError, KeyError, TypeError):
        raise NetworkError("Ungültige Antwort des IANA-RDAP-Verzeichnisses.") from None


def domain_provider(domain):
    tld = domain.rsplit(".", 1)[-1]
    if tld in DOMAIN_RDAP_SERVICES:
        return DOMAIN_RDAP_SERVICES[tld]
    for names, urls in bootstrap("dns"):
        if tld in names:
            return next((u for u in urls if u.startswith("https://")), None)
    return None


def https_rdap_url(value):
    if not isinstance(value, str) or any(ord(c) < 33 for c in value):
        return False
    try:
        parsed = urlsplit(value)
        return (parsed.scheme == "https" and bool(parsed.hostname) and parsed.port in (None, 443)
                and not parsed.username and not parsed.password and not parsed.fragment and not parsed.query)
    except ValueError:
        return False


@lru_cache(maxsize=1)
def registrar_directory():
    status, _, body = fetch_https(REGISTRAR_DIRECTORY)
    if status != 200:
        raise NetworkError(f"IANA-Registrarverzeichnis nicht verfügbar (HTTP {status}).")
    try:
        records = csv.DictReader(io.StringIO(body.decode("utf-8-sig")))
        if not {"ID", "Status", "RDAP Base URL"}.issubset(records.fieldnames or []):
            raise ValueError
        providers = {}
        for record in records:
            identifier = (record.get("ID") or "").strip()
            url = (record.get("RDAP Base URL") or "").strip()
            if (record.get("Status") or "").strip() == "Accredited" and identifier.isdigit() and https_rdap_url(url):
                providers[identifier] = url.rstrip("/") + "/"
        if not providers:
            raise ValueError
        return providers
    except (ValueError, UnicodeError, csv.Error):
        raise NetworkError("Ungültige Antwort des IANA-Registrarverzeichnisses.") from None


def network_provider(ip):
    address = ipaddress.ip_address(ip)
    matches = []
    for prefixes, urls in bootstrap("ipv4" if address.version == 4 else "ipv6"):
        for prefix in prefixes:
            network = ipaddress.ip_network(prefix)
            if address in network:
                matches.append((network.prefixlen, next((u for u in urls if u.startswith("https://")), None)))
    return max(matches, key=lambda item: item[0])[1] if matches else None


def make_plan(module, domain="", options=None):
    options = options or {}
    plan = {"module": module, "domain": normalize_domain(domain) if module == "domain" else "", "options": {key: bool(options.get(key)) for key in OPTIONS}, "recipients": [], "errors": [], "provider": None, "allowed_rdap_hosts": [], "registrars": {}}
    if module == "domain":
        registered, warning = registration_domain(plan["domain"]) if (options.get("rdap") or options.get("whois")) else (plan["domain"], "")
        plan["registration_domain"] = registered
        if warning:
            plan["errors"].append(warning)
    recipients = plan["recipients"]
    recipients.append(["DNS-Auflösung", f"Resolver der Installation: {resolver_description()}", "Abgefragte Domainnamen und Dienstnamen; der Resolver kann rekursiv weitere DNS-Server kontaktieren."])
    if module == "domain":
        if options.get("tls") or options.get("http"):
            recipients.append(["TLS / HTTPS", plan["domain"] + ":443", "Zieldomain (SNI/Host), öffentliche Server-IP des Betreibers; keine Aktenzeichen oder Header. HTTPS ohne automatisches Folgen von Weiterleitungen."])
        if options.get("rdap"):
            try:
                plan["provider"] = domain_provider(plan["registration_domain"])
                if plan["provider"]:
                    host = urlsplit(plan["provider"]).hostname
                    plan["allowed_rdap_hosts"].append(host)
                    recipients.append(["Domain-RDAP", host, f"Registrierungsdomain {plan['registration_domain']}; kein Aktenzeichen."])
                else:
                    plan["errors"].append("Für diese Domainendung ist kein HTTPS-RDAP-Dienst im IANA-Verzeichnis gefunden worden.")
            except NetworkError as exc:
                plan["errors"].append(str(exc))
            if plan["provider"] and not plan["registration_domain"].endswith(".de"):
                try:
                    plan["registrars"] = registrar_directory()
                    hosts = sorted({urlsplit(u).hostname for u in plan["registrars"].values()})
                    plan["allowed_rdap_hosts"].extend(hosts)
                    recipients.append(["Registrar-RDAP (nur der zuständige Anbieter)", ", ".join(hosts), "Registrierungsdomain an den über seine IANA-ID benannten zuständigen Registrar, falls kein RDAP-Link vorliegt. Weitere Domainverweise bleiben auf die ausgewiesene Abfragekette begrenzt. Kein Aktenzeichen."])
                except NetworkError as exc:
                    plan["errors"].append("Registrar-Ergänzung nicht verfügbar; die Registry-Abfrage bleibt möglich. " + str(exc))
        if options.get("whois"):
            recipients.append(["Klassische WHOIS-Abfragekette (unverschlüsselt, TCP 43)",
                               "whois.iana.org → dort genannte Registry-/Registrar-WHOIS-Dienste und deren weitere WHOIS-Verweise (öffentliche Ziele, TCP 43)",
                               f"Registrierungsdomain {plan['registration_domain']}, gegebenenfalls deren TLD, sowie VeriSign-Abfragevarianten. Kein Aktenzeichen. Die Folgedienste werden erst durch die Antworten bekannt, bis zu acht zusätzliche Dienste werden verfolgt und im Bericht einzeln dokumentiert."])
        if options.get("rdap"):
            plan["follow_domain_rdap"] = True
            recipients.append(["Domain-RDAP-Weiterverweise (HTTPS)",
                               "Von der Registry bzw. Folgediensten benannte öffentliche Registrar-RDAP-Dienste (HTTPS, Port 443)",
                               f"Nur weitere Domainabfragen für {plan['registration_domain']}, keine Kontakt-/Entity-Abfragen. Die genauen Folgedienste werden aus den Antworten ermittelt; maximal acht Abfragen einschließlich Weiterleitungen. Keine Aktenzeichen oder Zugangsdaten."])
    if options.get("network"):
        try:
            hosts = set()
            for kind in ("ipv4", "ipv6"):
                for _, urls in bootstrap(kind):
                    hosts.update(urlsplit(u).hostname for u in urls if u.startswith("https://"))
            plan["allowed_rdap_hosts"].extend(sorted(hosts))
            recipients.append(["Netzwerk-RDAP (je nach IP zuständiger Dienst)", ", ".join(sorted(hosts)), "Maximal drei öffentliche IP-Adressen aus DNS bzw. Transportheadern. Der vollständige Header und das Aktenzeichen werden nicht übertragen."])
        except NetworkError as exc:
            plan["errors"].append(str(exc))
    if options.get("rdap") or options.get("network"):
        recipients.append(["RDAP-Dienstverzeichnis", "data.iana.org", "Abruf öffentlicher Anbieterlisten dns.json / ipv4.json / ipv6.json. Keine Untersuchungsdaten; Verzeichnis wird im Prozess zwischengespeichert."])
    if plan["registrars"]:
        recipients.append(["Registrar-Dienstverzeichnis", "www.iana.org", "Abruf der öffentlichen Registrar-IDs und RDAP-Basisadressen. Keine Untersuchungsdaten; Verzeichnis wird im Prozess zwischengespeichert."])
    return plan


def get_rdap(url, allowed_hosts):
    for _ in range(4):
        host = urlsplit(url).hostname
        if host not in allowed_hosts:
            raise NetworkError("RDAP-Weiterleitung zu einem nicht im Abfrageplan enthaltenen Anbieter gestoppt.")
        status, headers, body = fetch_https(url, limit=256 * 1024)
        if status in (301, 302, 303, 307, 308):
            location = next((v for k, v in headers.items() if k.lower() == "location"), "")
            if not location:
                raise NetworkError("RDAP-Weiterleitung ohne Ziel.")
            url = urljoin(url, location)
            continue
        if status != 200:
            raise NetworkError(f"RDAP-Dienst antwortet mit HTTP {status}; keine Daten bestätigt.")
        try:
            data = json.loads(body)
            if not isinstance(data, dict):
                raise ValueError
        except ValueError:
            raise NetworkError("RDAP-Antwort ist kein gültiges JSON-Objekt.") from None
        return data, body, url
    raise NetworkError("Zu viele RDAP-Weiterleitungen.")


def rdap_text(value):
    if isinstance(value, list):
        return ", ".join(filter(None, (rdap_text(item) for item in value)))
    return "" if value is None else str(value)


def rdap_list(data, key, limit=20):
    value = data.get(key)
    return value[:limit] if isinstance(value, list) else []


def rdap_notices(data):
    rows = []
    for key, label in (("notices", "Hinweis"), ("remarks", "Anmerkung"), ("redacted", "Redigierte Angabe")):
        for notice in rdap_list(data, key):
            if not isinstance(notice, dict):
                continue
            if key == "redacted":
                parts = [rdap_text(notice.get(part, {}).get("description") or notice.get(part, {}).get("type", ""))
                         for part in ("name", "reason") if isinstance(notice.get(part), dict)]
            else:
                parts = [rdap_text(notice.get("title", "")), rdap_text(notice.get("description", ""))]
            value = " / ".join(filter(None, parts))
            if value:
                rows.append([label, value])
    return rows


def rdap_entities(data):
    pending = [(entity, 1) for entity in reversed(rdap_list(data, "entities"))]
    count = 0
    while pending and count < 80:
        entity, depth = pending.pop()
        if not isinstance(entity, dict):
            continue
        yield entity
        count += 1
        if depth < 4:
            pending.extend((child, depth + 1) for child in reversed(rdap_list(entity, "entities")))


def rdap_rows(data):
    rows = []
    for key, label in (("ldhName", "Domain"), ("handle", "Kennung"), ("name", "Netzname"), ("type", "Typ"), ("startAddress", "Netzanfang"), ("endAddress", "Netzende"), ("country", "Land laut Registrierungsdatensatz"), ("port43", "WHOIS-Dienst laut RDAP")):
        if key in data:
            rows.append([label, str(data[key])])
    if rdap_list(data, "status"):
        rows.append(["Status", rdap_text(rdap_list(data, "status"))])
    for event in rdap_list(data, "events"):
        if isinstance(event, dict):
            rows.append([str(event.get("eventAction", "Ereignis")), str(event.get("eventDate", ""))])
    for nameserver in rdap_list(data, "nameservers", 32):
        if isinstance(nameserver, dict) and nameserver.get("ldhName"):
            rows.append(["Nameserver", str(nameserver["ldhName"])])
    for entity in rdap_entities(data):
        label = rdap_text(rdap_list(entity, "roles")) or "Kontakt"
        names = [str(entity.get("handle", ""))]
        card = entity.get("vcardArray", [])
        details = []
        if isinstance(card, list) and len(card) > 1 and isinstance(card[1], list):
            for entry in card[1]:
                if not isinstance(entry, list) or len(entry) < 4:
                    continue
                if entry[0] in ("fn", "org"):
                    names.append(rdap_text(entry[3]))
                elif entry[0] in ("email", "tel", "adr"):
                    value = rdap_text(entry[3])
                    if entry[0] == "adr" and isinstance(entry[1], dict):
                        value = rdap_text(entry[1].get("label")) or value
                    if value:
                        details.append([label + " / " + {"email": "E-Mail", "tel": "Telefon", "adr": "Anschrift"}[entry[0]], value])
        rows.append([label, " / ".join(dict.fromkeys(n for n in names if n)) or "Keine öffentlichen Kontaktangaben im RDAP-Datensatz."])
        rows.extend(details)
        rows.extend(rdap_notices(entity))
    rows.extend(rdap_notices(data))
    if data.get("ldhName") and not any("registrant" in rdap_list(entity, "roles") for entity in rdap_entities(data)):
        rows.append(["Domaininhaber", "Kein öffentlicher Inhaberkontakt in dieser RDAP-Antwort. Weiterführende Registrar-Daten und Hinweise gegebenenfalls in separaten Abschnitten; fehlende Angaben belegen keine Datenschutzsperre."])
    return rows


def add_rdap_section(report, title, url, allowed_hosts, follow_domain=None, domain=None, plan=None):
    if follow_domain:
        lookup = (lambda data: registrar_query(data, follow_domain, plan)) if plan else None
        chain = walk_domain_rdap(url, follow_domain, allowed_hosts, fetch_https, registrar_lookup=lookup)
        section(report, "RDAP-Abfragekette", [["Abgefragte Adressen", "\n".join(step["url"] for step in chain["steps"])],
                ["Ende / Abbruch", chain["reason"]], ["Offene Adressen", "\n".join(chain["pending"]) or "Keine"]],
                status="ok" if chain["complete"] else "unavailable", note="Registry- und Registrar-Antworten sowie HTTP-Weiterleitungen werden einzeln erhalten. Doppelte Verweise werden nicht erneut abgefragt.")
        for number, rec in enumerate(chain["steps"], 1):
            try:
                rows = rdap_rows(rec["data"]) if rec["data"] else []
            except (ValueError, TypeError, KeyError, AttributeError, IndexError):
                rows = []
                rec["error"] = "Die Felder dieser RDAP-Antwort konnten nicht vollständig interpretiert werden."
            rows += [["HTTP-Status", str(rec["status"]) if rec["status"] is not None else "Keine Antwort"],
                     ["Abfragezeitpunkt (UTC)", rec["captured_at"]], ["Verweis von", rec["parent"] or "Dienst aus dem Abfrageplan"],
                     ["Weitere Verweise", "\n".join(rec["links"]) or "Keine"], ["SHA-256 der Antwortbytes", rec["sha256"] or "Keine Antwort"]]
            note = rec["error"] or "Registrierungsangaben der jeweiligen Quelle; keine Bestätigung des tatsächlichen Nutzers oder Standorts."
            if len(rec["raw"]) > 16384:
                note += " Rohdaten-Auszug auf 16.384 Zeichen begrenzt; die Prüfsumme bezieht sich auf alle empfangenen Antwortbytes."
            section(report, title if number == 1 else f"{title} / Stufe {number}", rows,
                    status="unavailable" if rec["error"] else "ok", raw=rec["raw"][:16384], note=note, source=rec["url"])
            report["sources"].append(rec["url"])
        return
    try:
        data, body, final_url = get_rdap(url, allowed_hosts)
        if data.get("errorCode") or (domain is not None and normalize_domain(data.get("ldhName", "")) != domain):
            raise NetworkError("RDAP-Antwort enthält keinen passenden Domain-Datensatz.")
        raw = body.decode("utf-8", "replace")
        section(report, title, rdap_rows(data), raw=raw, source=final_url,
                note="Registrierungsdaten, keine Bestätigung des tatsächlichen Nutzers oder physischen Standorts. SHA-256 der HTTPS-Antwort: " + hashlib.sha256(body).hexdigest())
        report["sources"].append(final_url)
        return data, final_url
    except NetworkError as exc:
        section(report, title, [], status="unavailable", note=str(exc), source=url)
    except (ValueError, TypeError, KeyError, AttributeError, IndexError):
        section(report, title, [], status="unavailable", note="RDAP-Abfrage fehlgeschlagen, Antwort ungültig oder außerhalb des freigegebenen Abfrageplans.", source=url)
    return None


def registrar_query(data, domain, plan):
    # Use the registrar's public IANA ID rather than following arbitrary links.
    # Every possible destination was loaded and disclosed before consent.
    for entity in rdap_entities(data):
        if "registrar" not in rdap_list(entity, "roles"):
            continue
        for identifier in rdap_list(entity, "publicIds"):
            if isinstance(identifier, dict) and str(identifier.get("type", "")).lower() == "iana registrar id":
                provider = plan.get("registrars", {}).get(str(identifier.get("identifier", "")))
                if provider and https_rdap_url(provider) and urlsplit(provider).hostname in plan["allowed_rdap_hosts"]:
                    return provider.rstrip("/") + "/domain/" + quote(domain)
    # Some registries supply only an RFC 9083 related link. Accept an exact
    # domain lookup at a base address already present in the approved directory.
    for link in rdap_list(data, "links"):
        if not isinstance(link, dict) or link.get("rel") != "related" or str(link.get("type", "")).split(";", 1)[0].lower() != "application/rdap+json":
            continue
        url = link.get("href")
        if not https_rdap_url(url):
            continue
        for provider in set(plan.get("registrars", {}).values()):
            if url == provider.rstrip("/") + "/domain/" + quote(domain) and urlsplit(url).hostname in plan["allowed_rdap_hosts"]:
                return url
    return None


def add_domain_registration(report, domain, plan):
    provider = plan.get("provider")
    if not provider:
        section(report, "Domain-RDAP / Registrierungsdaten", [], status="unavailable", note="Kein freigegebener RDAP-Dienst verfügbar; siehe Abfrageplan.")
        return
    result = add_rdap_section(report, "Domain-RDAP / Registrierungsdaten", provider.rstrip("/") + "/domain/" + quote(domain), plan["allowed_rdap_hosts"], domain=domain, follow_domain=domain if plan.get("follow_domain_rdap") else None, plan=plan)
    if result:
        data, final_url = result
        registrar = registrar_query(data, domain, plan)
        if registrar and registrar != final_url:
            add_rdap_section(report, "Registrar-RDAP / Kontakte und Datenschutzhinweise", registrar, plan["allowed_rdap_hosts"], domain=domain)
    if domain.endswith(".de"):
        report["limitations"].append("DENIC-RDAP liefert wie das öffentliche Port-43-WHOIS technische Daten. Öffentlich verfügbare Inhaberdaten juristischer Personen (z. B. Vereinsnamen) werden separat im DENIC-Web-WHOIS veröffentlicht und hier nicht automatisch abgerufen. Aus fehlenden Inhaberdaten ist kein Datenschutzstatus ableitbar.")
        section(report, "DENIC-Web-WHOIS / Inhaberauskunft", [["Manuelle Abfrage", "https://webwhois.denic.de/"], ["Domain", domain]], status="unavailable", note="Inhaberdaten nicht automatisch abgefragt. Für öffentlich verfügbare Organisations- und Vereinsnamen die Domain im DENIC-Web-WHOIS prüfen. Der Link ist ein weiterführender Hinweis, keine abgefragte Quelle.")


def add_networks(report, ips, allowed_hosts=None):
    report["sources"].append("https://data.iana.org/rdap/ipv4.json und ipv6.json (Dienstverzeichnis)")
    for ip in ips[:3]:
        if not is_public(ip):
            continue
        if allowed_hosts == []:
            section(report, f"Netzwerk-RDAP: {ip}", [], status="unavailable", note="Kein Netzwerk-RDAP-Anbieter im bestätigten Abfrageplan verfügbar.")
            continue
        try:
            provider = network_provider(ip)
            if not provider:
                raise NetworkError("Kein zuständiger HTTPS-RDAP-Dienst gefunden.")
            add_rdap_section(report, f"Netzwerk-RDAP: {ip}", provider.rstrip("/") + "/ip/" + quote(ip, safe=":"), [urlsplit(provider).hostname] if allowed_hosts is None else allowed_hosts)
        except NetworkError as exc:
            section(report, f"Netzwerk-RDAP: {ip}", [], status="unavailable", note=str(exc))


def dns_record(domain, kind):
    try:
        answer = resolver().resolve(domain, kind, search=False)
        records = list(answer)
        return {"kind": kind, "values": [str(value) for value in records[:32]], "ttl": answer.rrset.ttl,
                "status": "ok", "note": "Ausgabe auf 32 Einträge begrenzt." if len(records) > 32 else ""}
    except dns.resolver.NXDOMAIN:
        return {"kind": kind, "values": [], "status": "unavailable", "note": "NXDOMAIN: Name laut Resolver nicht vorhanden."}
    except dns.resolver.NoAnswer:
        return {"kind": kind, "values": [], "status": "empty", "note": "Kein Eintrag dieses Typs."}
    except dns.exception.DNSException:
        return {"kind": kind, "values": [], "status": "unavailable", "note": "DNS-Abfrage fehlgeschlagen oder Zeitlimit erreicht."}


def tls_section(report, domain, ips):
    try:
        with open_tls(domain, ips) as sock:
            cert = x509.load_der_x509_certificate(sock.getpeercert(binary_form=True))
            try:
                names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                names = []
            section(report, "TLS-Zertifikat und Verbindung", [
                ["Prüfung", "Hostnamen- und Vertrauenskette durch TLS-Bibliothek erfolgreich geprüft"],
                ["Verbunden mit", ips[0]], ["TLS-Version", sock.version()], ["Cipher", sock.cipher()[0]],
                ["Subject", cert.subject.rfc4514_string()], ["Aussteller", cert.issuer.rfc4514_string()],
                ["Gültig ab (UTC)", cert.not_valid_before_utc.isoformat()], ["Gültig bis (UTC)", cert.not_valid_after_utc.isoformat()],
                ["DNS-Namen", ", ".join(names)], ["Seriennummer", hex(cert.serial_number)],
                ["SHA-256 Zertifikat (DER)", cert.fingerprint(hashes.SHA256()).hex()],
            ], source=f"TLS-Verbindung zu {domain}:443", note="Ein Verbindungsaufbau mit System-Vertrauensspeicher. Kein vollständiger Protokoll-/Cipher-Scan, keine OCSP-/CRL-Sperrprüfung. Ein konfigurierter TLS-Proxy kann das beobachtete Zertifikat ersetzen.")
    except NetworkError as exc:
        section(report, "TLS-Zertifikat und Verbindung", [], status="unavailable", note=str(exc), source=f"{domain}:443")


def analyze_domain(case, original, plan):
    domain = normalize_domain(original)
    registered = plan.get("registration_domain") or registration_domain(domain)[0]
    options = plan["options"]
    report = new_report("domain", case, domain, original)
    report["disclosure"] = plan["recipients"]
    report["sources"].append("DNS-Resolver der Installation: " + resolver_description())
    report["limitations"] += [
        "Momentaufnahme zum Abfragezeitpunkt. DNS- und Registrierungsdaten können sich ändern; DNSSEC wird nicht eigenständig validiert.",
        "RDAP und klassisches WHOIS dokumentieren veröffentlichte Registrierungsangaben einschließlich gelieferter Datenschutz- und Redigierungshinweise. Verdeckte, gelöschte oder nicht veröffentlichte Angaben können nicht ermittelt werden.",
        "Registrierungsabfragen verwenden die registrierbare Basisdomain aus dem mitgelieferten Public-Suffix-Snapshot (ohne automatischen Listendownload). DNS, TLS und HTTPS untersuchen weiterhin die eingegebene Domain.",
        "Netzwerk-RDAP auf maximal drei öffentliche IP-Adressen begrenzt; TLS und HTTPS prüfen die erste öffentliche DNS-Adresse. Keine ASN-/BGP-Zuordnung und keine Standortermittlung.",
        "Ein verifiziertes TLS-Zertifikat ist kein Nachweis der Seriosität eines Angebots.",
    ]
    for error in plan["errors"]:
        report["summary"].append({"level": "notice", "text": error})
    if registered != domain:
        report["summary"].append({"level": "info", "text": f"Die Eingabe ist eine Subdomain. RDAP/WHOIS beziehen sich auf {registered}; DNS, TLS und HTTPS auf {domain}."})
    with ThreadPoolExecutor(max_workers=4) as pool:
        answers = list(pool.map(lambda kind: dns_record(domain, kind), ("A", "AAAA", "NS", "MX", "TXT", "SOA", "CAA")))
    ips = [ip for answer in answers if answer["kind"] in ("A", "AAAA") for ip in answer["values"]]
    for answer in answers:
        section(report, "DNS: " + answer["kind"], [[str(index), value] for index, value in enumerate(answer["values"], 1)], status=answer["status"],
                note=f"TTL: {answer.get('ttl', '–')} Sekunden. {answer['note']}", source="DNS über " + resolver_description())
    public = bool(ips) and all(is_public(ip) for ip in ips)
    report["summary"].append({"level": "info", "text": f"{len(ips)} IP-Adresse(n) in den DNS-Antworten erkannt."})
    if not public:
        report["summary"].append({"level": "warning", "text": "Keine ausschließlich öffentlichen DNS-Zieladressen. Verbindungen zum Ziel und Netzwerk-RDAP wurden gesperrt."})
    if options.get("whois"):
        add_whois(report, registered)
        report["limitations"].append("WHOIS-Verweise werden bis zu acht weitere Dienste nach IANA verfolgt, nicht nur bis zur ersten Registrar-Antwort. Schleifen werden dedupliziert. Zeit-/Größenlimits, Verbindungsfehler und nicht unterstützte Protokolle werden als unvollständig ausgewiesen. RWHOIS ist ein anderes Protokoll und wird nicht fälschlich als WHOIS auf Port 43 abgefragt.")
    if options.get("rdap"):
        if plan.get("registrars"):
            report["sources"].append(REGISTRAR_DIRECTORY + " (Dienstverzeichnis laut Abfrageplan)")
        add_domain_registration(report, registered, plan)
    if options.get("network"):
        if public:
            add_networks(report, ips, plan["allowed_rdap_hosts"])
        else:
            section(report, "Netzwerk-RDAP", [], status="unavailable", note="Keine freigegebenen öffentlichen IP-Adressen.")
    if options.get("tls"):
        if public:
            tls_section(report, domain, ips)
        else:
            section(report, "TLS-Zertifikat und Verbindung", [], status="unavailable", note="Keine freigegebenen öffentlichen IP-Adressen.")
    if options.get("http"):
        url = f"https://{domain}/"
        try:
            if not public:
                raise NetworkError("Keine freigegebenen öffentlichen IP-Adressen.")
            status, headers, _ = fetch_https(url, method="HEAD", addresses=ips)
            selected = {"server", "location", "content-type", "strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy"}
            rows = [["HTTP-Status", str(status)]] + [[k, v] for k, v in headers.items() if k.lower() in selected]
            section(report, "HTTPS-Antwortheader", rows, source=url, note="HEAD-Anfrage an Port 443. Weiterleitungen werden dokumentiert und nicht verfolgt; keine Seiteninhalte, Cookies oder Skripte geladen.")
            report["sources"].append(url)
        except NetworkError as exc:
            section(report, "HTTPS-Antwortheader", [], status="unavailable", note=str(exc), source=url)
    unavailable = sum(s["status"] == "unavailable" for s in report["sections"])
    report["summary"].append({"level": "notice" if unavailable else "info", "text": f"{unavailable} Prüfbereich(e) nicht verfügbar. Fehlende Ergebnisse sind keine unauffälligen Befunde."})
    return finish(report)
