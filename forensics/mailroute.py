"""Describe transport IPs from their explicit positions, without DNS guesses."""
import ipaddress
import re

from .mailparse import mask_header, split_clauses


def extract_ips(values):
    addresses = []
    for value in values:
        for candidate in re.findall(r"(?:IPv6:)?[0-9A-Fa-f:.]+", str(value)):
            try:
                address = ipaddress.ip_address(candidate.removeprefix("IPv6:").strip("."))
            except ValueError:
                continue
            if str(address) not in addresses:
                addresses.append(str(address))
    return addresses[:30]


def received_parts(value):
    # Only top-level keywords delimit clauses: host comments may contain words
    # such as "from" or "by", but their IP literals still belong to the clause.
    text = next(split_clauses(value))
    markers = list(re.finditer(r"\b(from|by|with|via|id|for)\s+", mask_header(text, quotes=True), re.I))
    parts = {}
    for index, marker in enumerate(markers):
        end = markers[index + 1].start() if index + 1 < len(markers) else len(text)
        parts.setdefault(marker[1].lower(), text[marker.end():end].strip())
    return parts


def station_name(value):
    text = mask_header(value).strip()
    return text.split()[0].strip("[]") if text else "nicht angegeben"


def describe_hop(parts):
    lines = ["Sendende Station: " + (parts.get("from") or "nicht angegeben"),
             "Empfangende Station: " + (parts.get("by") or "nicht angegeben")]
    if parts.get("with"):
        lines.append("Übertragungsverfahren: " + parts["with"])
    return "\n".join(lines)


def address_type(ip):
    address = ipaddress.ip_address(ip)
    if address.version == 6 and address.ipv4_mapped:
        return "In IPv6 dargestellte IPv4-Adresse: " + address_type(str(address.ipv4_mapped))
    if address.is_loopback:
        return "Lokale Loopback-Adresse: Kommunikation innerhalb desselben Systems."
    if address.is_link_local:
        return "Link-lokale Adresse: nur im unmittelbar verbundenen Netz nutzbar."
    if address.is_multicast:
        return "Multicast-Adresse: Gruppenadresse, kein einzelner Absenderanschluss."
    if any(address in ipaddress.ip_network(net) for net in (
        "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
    ) if address.version == ipaddress.ip_network(net).version):
        return "Dokumentationsadresse aus einem Beispielnetz; keine öffentliche Anschlussadresse."
    if any(address in ipaddress.ip_network(net) for net in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
    ) if address.version == ipaddress.ip_network(net).version):
        return "Private interne Netzwerkadresse; für eine Anschlusszuordnung außerhalb dieses Netzes nicht geeignet."
    if address in ipaddress.ip_network("100.64.0.0/10"):
        return "Geteilter Adressbereich für Provider-NAT; keine eindeutige öffentliche Anschlussadresse."
    if address.is_global and not address.is_reserved:
        return "Öffentlich routbare " + ("IPv4" if address.version == 4 else "IPv6") + "-Adresse."
    return "Reservierte oder sonstige nicht öffentlich routbare Adresse."


def ip_inventory(msg, received, auth_records):
    observations = {}

    def record(ip, role, evidence):
        if ip not in observations and len(observations) >= 30:
            return
        items = observations.setdefault(ip, [])
        entry = role + ". Fundstelle: " + evidence + "."
        if entry not in items:
            items.append(entry)

    last_incoming = []
    for number, value in enumerate(reversed(received), 1):
        parts = received_parts(value)
        protocol = parts.get("with", "").split()[0].upper() if parts.get("with") else ""
        authenticated = protocol in ("ESMTPA", "ESMTPSA", "SMTPA", "SMTPSA", "UTF8SMTPA", "UTF8SMTPSA")
        for side in ("from", "by"):
            for ip in extract_ips([parts.get(side, "")]):
                host = station_name(parts.get(side, ""))
                if side == "from":
                    if authenticated:
                        role = "Möglicher Absender-Endpunkt bei authentifizierter Einlieferung; kann ein Mailprogramm, eine Anwendung oder ein Server sein"
                    elif number == len(received):
                        role = "Einlieferndes System am letzten dokumentierten Empfang; Mailserver, Weiterleitungsdienst oder direkt sendender Endpunkt"
                    elif number == 1:
                        role = "Früheste erkennbare Sendestation; möglicher Mailserver der Absenderseite"
                    else:
                        role = "Weiterleitender Mailserver / Zwischenstation"
                    if number == len(received):
                        last_incoming.append(ip)
                elif number == len(received):
                    role = "Letzter dokumentierter Empfangsserver; Station auf der Empfängerseite des erfassten Transportwegs"
                else:
                    role = "Empfangender Mailserver / Zwischenstation im weiteren Transportweg"
                record(ip, role, f"Received-Station {number}, {side} {host}")
        assigned = extract_ips([parts.get("from", ""), parts.get("by", "")])
        for ip in extract_ips([value]):
            if ip not in assigned:
                record(ip, "Weitere IP-Angabe ohne eindeutig erkennbare Transportrolle", f"Received-Station {number}")
    for index, value in enumerate(msg.get_all("X-Originating-IP", []), 1):
        for ip in extract_ips([value]):
            record(ip, "Möglicher ursprünglicher Einlieferungs-Endpunkt, etwa beim Versand über Webmail; ein Proxy oder vorgeschalteter Dienst ist ebenfalls möglich", f"X-Originating-IP #{index}")
    for auth in auth_records:
        props = auth["properties"]
        for key in ("client-ip", "smtp.remote-ip"):
            for ip in extract_ips([props.get(key, "")]):
                record(ip, "Sendende IP, die im protokollierten Prüfergebnis genannt wird", auth["source"] + ", " + key)
    rows = [[ip, address_type(ip) + "\n" + "\n".join(items)] for ip, items in observations.items()]
    return rows, list(observations), [ip for ip in last_incoming if ip in observations]
