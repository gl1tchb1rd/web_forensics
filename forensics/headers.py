import re
from datetime import timezone
from email import policy
from email.parser import HeaderParser
from email.utils import getaddresses, parsedate_to_datetime

from .report import finish, new_report, section
from .mailauth import add_authentication
from .mailroute import describe_hop, extract_ips, ip_inventory, received_parts

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
    report["sources"].append("Vom Benutzer übermittelter E-Mail-Header.")
    report["limitations"] += [
        "Grundlage ist der übermittelte E-Mail-Header. Ausgewertet werden die darin protokollierten Transportstationen und Prüfergebnisse der Mailsysteme.",
        "Ein zugelassener Versandweg kann auch über einen beauftragten Versanddienst oder ein kompromittiertes Konto genutzt werden. Ob ein unberechtigter Kontozugriff vorlag und welche Person die Nachricht veranlasst hat, lässt sich erst mit ergänzenden Anmelde- und Serverprotokollen klären.",
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
        route.append([f"Station {number}", describe_hop(received_parts(hop)) + f"\nUTC: {timestamp.isoformat() if timestamp else 'nicht eindeutig bestimmbar'} | Abstand zur vorherigen Station: {delta}"])
        previous = timestamp
    section(report, "Transportweg laut Received", route, status="ok" if route else "unavailable",
            note="In Versandrichtung dargestellt: früheste eingetragene Station zuerst, zuletzt der letzte dokumentierte Empfang. Eine Station beschreibt jeweils die Übergabe zwischen zwei Systemen.",
            source="Received-Felder, Reihenfolge und Zeitangaben aus der Eingabe")
    report["summary"].append({"level": "info", "text": f"{len(received)} Received-Stationen im Header erkannt."})

    auth_summary, auth_records = add_authentication(report, msg, sender_domain=sender)
    ip_rows, ips, last_incoming = ip_inventory(msg, received, auth_records)
    section(report, "Erfasste IP-Adressen und ihre Rolle", ip_rows, status="ok" if ips else "empty",
            note="Jede Adresse wird mit ihrer Fundstelle und der dort erkennbaren Rolle aufgeführt (höchstens 30 verschiedene Adressen). Eine Endpunkt-IP kann zu einem Anschluss, einem VPN, einem Proxy oder einem Server gehören; der Header unterscheidet diese Möglichkeiten nicht sicher.",
            source="Received, X-Originating-IP und IP-Angaben in Authentication-Results / Received-SPF")
    ip_summary = [{"level": "info", "text": f"{len(ips)} unterschiedliche IP-Adresse(n) erfasst; Rollen und Fundstellen sind im IP-Verzeichnis erläutert."}]
    if last_incoming:
        ip_summary.append({"level": "info", "text": "Einliefernde IP-Adresse(n) beim letzten dokumentierten Empfang: " + ", ".join(dict.fromkeys(last_incoming)) + "."})
    report["summary"] = auth_summary + ip_summary + report["summary"]
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
