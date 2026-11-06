import hashlib
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

OPTIONS = ("rdap", "network", "tls", "http")


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
    for names, urls in bootstrap("dns"):
        if tld in names:
            return next((u for u in urls if u.startswith("https://")), None)
    return None


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
    plan = {"module": module, "domain": normalize_domain(domain) if module == "domain" else "", "options": {key: bool(options.get(key)) for key in OPTIONS}, "recipients": [], "errors": [], "provider": None, "allowed_rdap_hosts": []}
    recipients = plan["recipients"]
    recipients.append(["DNS-Auflösung", f"Resolver der Installation: {resolver_description()}", "Abgefragte Domainnamen und Dienstnamen; der Resolver kann rekursiv weitere DNS-Server kontaktieren."])
    if module == "domain":
        if options.get("tls") or options.get("http"):
            recipients.append(["TLS / HTTPS", plan["domain"] + ":443", "Zieldomain (SNI/Host), öffentliche Server-IP des Betreibers; keine Aktenzeichen oder Header. HTTPS ohne automatisches Folgen von Weiterleitungen."])
        if options.get("rdap"):
            try:
                plan["provider"] = domain_provider(plan["domain"])
                if plan["provider"]:
                    host = urlsplit(plan["provider"]).hostname
                    plan["allowed_rdap_hosts"].append(host)
                    recipients.append(["Domain-RDAP", host, "Vollständige eingegebene Domain; kein Aktenzeichen."])
                else:
                    plan["errors"].append("Für diese Domainendung ist kein HTTPS-RDAP-Dienst im IANA-Verzeichnis gefunden worden.")
            except NetworkError as exc:
                plan["errors"].append(str(exc))
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


def rdap_rows(data):
    rows = []
    for key, label in (("ldhName", "Domain"), ("handle", "Kennung"), ("name", "Netzname"), ("type", "Typ"), ("startAddress", "Netzanfang"), ("endAddress", "Netzende"), ("country", "Land laut Registrierungsdatensatz"), ("port43", "WHOIS-Dienst laut RDAP")):
        if key in data:
            rows.append([label, str(data[key])])
    if data.get("status"):
        rows.append(["Status", ", ".join(map(str, data["status"]))])
    for event in data.get("events", [])[:20]:
        rows.append([str(event.get("eventAction", "Ereignis")), str(event.get("eventDate", ""))])
    for entity in data.get("entities", [])[:20]:
        label = ", ".join(map(str, entity.get("roles", []))) or "Kontakt"
        names = [str(entity.get("handle", ""))]
        card = entity.get("vcardArray", [])
        if len(card) > 1 and isinstance(card[1], list):
            for entry in card[1]:
                if isinstance(entry, list) and len(entry) > 3 and entry[0] in ("fn", "org"):
                    names.append(str(entry[3]))
        rows.append([label, " / ".join(n for n in names if n)])
    return rows


def add_rdap_section(report, title, url, allowed_hosts):
    try:
        data, body, final_url = get_rdap(url, allowed_hosts)
        raw = body.decode("utf-8", "replace")
        section(report, title, rdap_rows(data), raw=raw, source=final_url,
                note="Registrierungsdaten, keine Bestätigung des tatsächlichen Nutzers oder physischen Standorts. SHA-256 der HTTPS-Antwort: " + hashlib.sha256(body).hexdigest())
        report["sources"].append(final_url)
    except NetworkError as exc:
        section(report, title, [], status="unavailable", note=str(exc), source=url)
    except (ValueError, TypeError, KeyError, AttributeError, IndexError):
        section(report, title, [], status="unavailable", note="RDAP-Abfrage fehlgeschlagen, Antwort ungültig oder außerhalb des freigegebenen Abfrageplans.", source=url)


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
    options = plan["options"]
    report = new_report("domain", case, domain, original)
    report["disclosure"] = plan["recipients"]
    report["sources"].append("DNS-Resolver der Installation: " + resolver_description())
    report["limitations"] += [
        "Momentaufnahme zum Abfragezeitpunkt. DNS- und Registrierungsdaten können sich ändern; DNSSEC wird nicht eigenständig validiert.",
        "RDAP ist der strukturierte Nachfolger von WHOIS. Diese Version führt keine klassischen Port-43-WHOIS-Abfragen aus. Verdeckte oder nicht veröffentlichte Angaben können nicht ermittelt werden.",
        "RDAP wird für die eingegebene Domain abgefragt. Bei Subdomains kann der Registry-Dienst keine Domainregistrierung liefern.",
        "Netzwerk-RDAP auf maximal drei öffentliche IP-Adressen begrenzt; TLS und HTTPS prüfen die erste öffentliche DNS-Adresse. Keine ASN-/BGP-Zuordnung und keine Standortermittlung.",
        "Ein verifiziertes TLS-Zertifikat ist kein Nachweis der Seriosität eines Angebots.",
    ]
    for error in plan["errors"]:
        report["summary"].append({"level": "notice", "text": error})
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
    if options.get("rdap"):
        if plan.get("provider"):
            add_rdap_section(report, "Domain-RDAP / Registrierungsdaten", plan["provider"].rstrip("/") + "/domain/" + quote(domain), plan["allowed_rdap_hosts"])
        else:
            section(report, "Domain-RDAP / Registrierungsdaten", [], status="unavailable", note="Kein freigegebener RDAP-Dienst verfügbar; siehe Abfrageplan.")
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
