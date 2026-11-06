import ipaddress
import re
from datetime import timezone
from email import policy
from email.parser import HeaderParser
from email.utils import getaddresses, parsedate_to_datetime

from .report import finish, new_report, section

MAX_HEADER_BYTES = 64 * 1024


def clean(value):
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "�", str(value)).replace("\n", " ").replace("\r", " ")


def mail_domain(value):
    addresses = getaddresses([str(value or "")])
    if len(addresses) != 1 or "@" not in addresses[0][1]:
        return ""
    return addresses[0][1].rsplit("@", 1)[1].lower().rstrip(".")


def parse_time(value):
    try:
        dt = parsedate_to_datetime(value.strip())
        return dt.astimezone(timezone.utc) if dt.tzinfo is not None else None
    except (ValueError, TypeError, OverflowError):
        return None


def extract_ips(values):
    addresses = []
    for value in values:
        # Parse candidates, never interpret arbitrary header strings as lookup URLs.
        for candidate in re.findall(r"(?:IPv6:)?[0-9A-Fa-f:.]+", str(value)):
            try:
                address = ipaddress.ip_address(candidate.removeprefix("IPv6:").strip("."))
            except ValueError:
                continue
            if str(address) not in addresses:
                addresses.append(str(address))
    return addresses[:30]


def analyze_header(case, original, enrich=False, plan=None):
    if not isinstance(original, str) or not original.strip():
        raise ValueError("Bitte einen vollständigen E-Mail-Header einfügen.")
    if len(original.encode("utf-8")) > MAX_HEADER_BYTES:
        raise ValueError("Der Header darf maximal 64 KiB umfassen.")
    if "\x00" in original:
        raise ValueError("Der Header enthält unzulässige Nullzeichen.")
    normalized = original.replace("\r\n", "\n").replace("\r", "\n")
    parts = normalized.split("\n\n", 1)
    if len(parts) == 2 and parts[1].strip():
        raise ValueError("Bitte ausschließlich den Header eingeben, ohne Nachrichtentext oder Anhänge.")
    header = parts[0]
    if len(header.splitlines()) > 1500:
        raise ValueError("Der Header enthält zu viele Zeilen (maximal 1500).")
    msg = HeaderParser(policy=policy.default).parsestr(header + "\n\n")
    if not list(msg.keys()):
        raise ValueError("Es wurden keine gültigen Headerfelder erkannt.")

    report = new_report("headers", case, "E-Mail-Header", original)
    report["sources"].append("Vom Benutzer übermittelter Header; Herkunft und Vollständigkeit nicht verifiziert.")
    report["limitations"] += [
        "Alle Headerfelder einschließlich Received und Authentication-Results können manipuliert sein. Eine vertrauenswürdige Empfangsgrenze ist nicht bekannt.",
        "SPF-, DKIM- und DMARC-Ergebnisse werden ausschließlich aus dem Header ausgelesen, nicht unabhängig bestätigt. DKIM benötigt zur vollständigen Prüfung auch den Nachrichteninhalt.",
        "Received-Reihenfolge und Zeitdifferenzen beruhen auf den eingetragenen Angaben. Sie belegen weder den tatsächlichen Absender noch dessen Standort.",
        "Die Prüfsumme bezieht sich auf die eingefügte UTF-8-Eingabe; Einfügen und Kopieren können die Originaldarstellung verändern.",
    ]
    rows = [[label, clean(msg.get(field, "Nicht angegeben"))] for field, label in [
        ("From", "From / sichtbarer Absender"), ("Reply-To", "Antwortadresse"),
        ("Return-Path", "Rücklaufadresse"), ("To", "Empfänger"), ("Subject", "Betreff"),
        ("Date", "Datum laut Header"), ("Message-ID", "Message-ID"),
        ("X-Mailer", "X-Mailer"), ("User-Agent", "User-Agent"),
    ]]
    section(report, "Absender und Nachrichtenmerkmale", rows, source="Übermittelte Headerfelder")
    for field in ("From", "Date", "Message-ID"):
        values = msg.get_all(field, [])
        if not values:
            report["summary"].append({"level": "notice", "text": f"Das Feld {field} fehlt."})
        elif len(values) > 1:
            report["summary"].append({"level": "warning", "text": f"Das Feld {field} kommt mehrfach vor ({len(values)}). Die Darstellung kann je nach Mailprogramm abweichen."})
    sender = mail_domain(msg.get("From"))
    for field in ("Reply-To", "Return-Path"):
        other = mail_domain(msg.get(field))
        if sender and other and sender != other:
            report["summary"].append({"level": "notice", "text": f"Die Domains von From und {field} unterscheiden sich. Das kann legitime technische Gründe haben und beweist keine Fälschung."})
    if msg.defects:
        report["summary"].append({"level": "warning", "text": "Der Parser hat Strukturfehler erkannt: " + ", ".join(type(d).__name__ for d in msg.defects)})

    received = [str(value) for value in msg.get_all("Received", [])]
    route = []
    previous = None
    for number, hop in enumerate(reversed(received), 1):
        timestamp = parse_time(hop.rsplit(";", 1)[-1]) if ";" in hop else None
        delta = "Nicht berechenbar"
        if timestamp and previous:
            seconds = int((timestamp - previous).total_seconds())
            delta = f"{seconds} Sekunden"
            if seconds < 0:
                report["summary"].append({"level": "warning", "text": f"Zeitwiderspruch vor Received-Station {number}: {seconds} Sekunden. Abweichende Serveruhren oder manipulierte Angaben sind mögliche Ursachen."})
            elif seconds > 3600:
                report["summary"].append({"level": "notice", "text": f"Zwischen Received-Station {number - 1} und {number} liegen laut Header mehr als 60 Minuten."})
        route.append([f"Station {number}", f"UTC: {timestamp.isoformat() if timestamp else 'nicht eindeutig bestimmbar'} | Abstand: {delta}\n{clean(hop)}"])
        previous = timestamp
    section(report, "Transportweg laut Received", route, status="ok" if route else "unavailable",
            note="Von unten nach oben gelesen (behauptete früheste Station zuerst). Keine Station ist automatisch vertrauenswürdig.",
            source="Received-Felder, Reihenfolge und Zeitangaben aus der Eingabe")
    report["summary"].append({"level": "info", "text": f"{len(received)} Received-Stationen im Header erkannt."})

    auth_rows = []
    for name in ("Authentication-Results", "ARC-Authentication-Results", "Received-SPF"):
        for index, value in enumerate(msg.get_all(name, []), 1):
            auth_rows.append([f"{name} #{index} (nicht verifiziert)", clean(value)])
    for index, signature in enumerate(msg.get_all("DKIM-Signature", []), 1):
        tags = dict(re.findall(r"(?:^|;)\s*([a-z]+)\s*=\s*([^;]+)", str(signature)))
        auth_rows.append([f"DKIM-Signature #{index}", f"Domain: {clean(tags.get('d', 'fehlt'))}; Selektor: {clean(tags.get('s', 'fehlt'))}; Algorithmus: {clean(tags.get('a', 'fehlt'))}. Signatur vorhanden, nicht geprüft."])
    section(report, "Authentifizierung laut Header", auth_rows, status="ok" if auth_rows else "unavailable",
            note="Keine eigenständige SPF-/DKIM-/DMARC-Prüfung. Auch eingetragene pass-Ergebnisse können gefälscht sein.", source="Authentication-Results, ARC, Received-SPF und DKIM-Signature")

    ips = extract_ips(received + msg.get_all("X-Originating-IP", []))
    section(report, "IP-Adressen im Transportheader", [[ip, "Öffentlich routbar" if ipaddress.ip_address(ip).is_global else "Nicht öffentlich routbar; keine externe Abfrage"] for ip in ips],
            note="Erwähnte Adressen, keine bestätigte Ursprungszuordnung.", source="Received und X-Originating-IP")
    if enrich:
        from .domain import add_networks
        from .network import is_public
        add_networks(report, [ip for ip in ips if is_public(ip)][:3], (plan or {}).get("allowed_rdap_hosts", []))
        report["disclosure"] = (plan or {}).get("recipients", [])
        report["limitations"].append("Externe Netzwerk-RDAP-Ergänzung auf höchstens drei öffentliche Header-IP-Adressen begrenzt.")
    else:
        report["sources"].append("Keine externen Abfragen durchgeführt.")
    section(report, "Übermittelter Originalheader", [], raw=original, source="Benutzereingabe, unverändert nach Empfang als UTF-8-Text")
    return finish(report)
