"""Interpret recorded authentication results; keep each evaluator identifiable."""
import re

from .mailparse import assignments, mask_header, split_clauses
from .report import section

METHODS = ("spf", "dkim", "dmarc")
RESULTS = {
    "pass": "Bestanden", "fail": "Nicht bestanden", "softfail": "Schwache Ablehnung",
    "neutral": "Keine Aussage zur Berechtigung", "none": "Keine anwendbare Prüfung",
    "temperror": "Vorübergehender Prüffehler", "permerror": "Dauerhafter Prüffehler",
    "policy": "Nach Richtlinie abgelehnt",
}
EXPLANATIONS = {
    "spf": {
        "pass": "Die geprüfte sendende IP war für die technische Absenderdomain (MAIL FROM bzw. HELO) zum Versand zugelassen. SPF allein bestätigt noch nicht die im Mailprogramm sichtbare From-Adresse.",
        "fail": "Die geprüfte sendende IP war für die technische Absenderdomain nicht zum Versand zugelassen.",
        "softfail": "Die SPF-Regel stuft die sendende IP als wahrscheinlich nicht zugelassen ein; dies ist schwächer als eine ausdrückliche Ablehnung (fail).",
        "neutral": "Die Domain trifft keine Aussage darüber, ob diese IP zum Versand zugelassen war.",
        "none": "Es wurde keine anwendbare SPF-Regel bzw. Prüfidentität gefunden. Eine Versandberechtigung ist damit weder bestätigt noch verneint.",
    },
    "dkim": {
        "pass": "Eine gültige elektronische Signatur der genannten Signaturdomain ist dokumentiert. Die von ihr erfassten Nachrichtenteile haben die Signaturprüfung bestanden.",
        "fail": "Die elektronische Signatur hat die Prüfung nicht bestanden. Beispielsweise kommen Änderungen an signierten Nachrichtenteilen als Ursache in Betracht.",
        "none": "Keine anwendbare DKIM-Signatur vorhanden.",
        "neutral": "Die Signatur ergab keine eindeutige Bestätigung, beispielsweise wegen eines nicht verwertbaren Formats.",
        "policy": "Die Signatur wurde nach den Regeln des prüfenden Systems nicht akzeptiert.",
    },
    "dmarc": {
        "pass": "Die im From-Feld sichtbare Absenderdomain wurde durch mindestens eine passende erfolgreiche SPF- oder DKIM-Prüfung bestätigt. Entscheidend ist dabei die Zuordnung der geprüften Domain zur sichtbaren Absenderdomain.",
        "fail": "Die im From-Feld sichtbare Absenderdomain wurde weder durch eine passende erfolgreiche SPF-Prüfung noch durch eine passende erfolgreiche DKIM-Prüfung bestätigt.",
        "none": "Keine anwendbare DMARC-Regel bzw. Prüfgrundlage gefunden. Das ist keine fehlgeschlagene DMARC-Prüfung.",
    },
}
SUMMARY_TEXT = {
    ("spf", "pass"): "Die sendende IP war für die geprüfte technische Absenderdomain zum Versand zugelassen.",
    ("spf", "fail"): "Die sendende IP war für die geprüfte technische Absenderdomain nicht zum Versand zugelassen.",
    ("dkim", "pass"): "Eine gültige Signatur der geprüften Signaturdomain ist dokumentiert.",
    ("dkim", "fail"): "Die elektronische Signatur hat die Prüfung nicht bestanden.",
    ("dmarc", "pass"): "Die sichtbare Absenderdomain wurde durch eine passende SPF- oder DKIM-Prüfung bestätigt.",
    ("dmarc", "fail"): "Die sichtbare Absenderdomain wurde nicht durch eine passende SPF- oder DKIM-Prüfung bestätigt.",
}


def authentication_results(msg):
    records = []
    for index, value in enumerate(msg.get_all("Authentication-Results", [])[:30], 1):
        clauses = list(split_clauses(value))
        evaluator = mask_header(clauses[0]).strip() or "nicht angegeben"
        for clause in clauses[1:]:
            text = mask_header(clause)
            match = re.match(r"\s*(spf|dkim|dmarc)(?:/\d+)?\s*=\s*([a-z]+)\b", text, re.I)
            if match:
                records.append({"method": match[1].lower(), "result": match[2].lower(),
                                "properties": assignments(text[match.end():]), "server": evaluator,
                                "source": f"Authentication-Results #{index}"})
    for index, value in enumerate(msg.get_all("Received-SPF", [])[:30], 1):
        match = re.match(r"\s*([a-z]+)\b", mask_header(value), re.I)
        if match and match[1].lower() in RESULTS:
            props = assignments(value)
            records.append({"method": "spf", "result": match[1].lower(), "properties": props,
                            "server": props.get("receiver", "nicht angegeben"), "source": f"Received-SPF #{index}"})
    return records


def result_label(result):
    return RESULTS.get(result, "Sonstiges Prüfergebnis") + f" ({result})"


def result_details(record):
    method, result, props = record["method"], record["result"], record["properties"]
    lines = [f"Prüfendes System: {record['server']}; Fundstelle: {record['source']}."]
    keys = {"spf": (("smtp.mailfrom", "Technische Absenderadresse / Domain"), ("envelope-from", "Technische Absenderadresse"), ("smtp.helo", "HELO-Domain"), ("helo", "HELO-Domain"), ("client-ip", "Geprüfte sendende IP")),
            "dkim": (("header.d", "Signaturdomain"), ("header.i", "Signaturidentität")),
            "dmarc": (("header.from", "Sichtbare Absenderdomain (From)"),)}[method]
    for key, label in keys:
        if key in props:
            lines.append(f"{label}: {props[key]}.")
    if result in ("temperror", "permerror"):
        explanation = "Die Prüfung konnte wegen eines " + ("vorübergehenden technischen Fehlers" if result == "temperror" else "dauerhaften Regel- oder Konfigurationsfehlers") + " nicht abschließend durchgeführt werden. Dies ist keine ausdrückliche Ablehnung der Versandberechtigung."
    else:
        explanation = EXPLANATIONS[method].get(result, "Der Ergebniscode wird mit dem Wortlaut des prüfenden Systems dokumentiert.")
    lines.append(explanation)
    return "\n".join(lines)


def add_authentication(report, msg, sender_domain=""):
    records = authentication_results(msg)
    rows, summary = [], []
    for method in METHODS:
        matching = [r for r in records if r["method"] == method]
        if not matching:
            rows.append([method.upper() + " — Kein Prüfergebnis im Header", "Ein Ergebnis für dieses Verfahren ist nicht eingetragen."])
            summary.append({"level": "notice", "text": method.upper() + ": Kein Prüfergebnis im Header."})
            continue
        outcomes = list(dict.fromkeys(r["result"] for r in matching))
        for record in matching:
            rows.append([method.upper() + " — " + result_label(record["result"]), result_details(record)])
        if len(outcomes) > 1:
            summary.append({"level": "notice", "text": method.upper() + ": Unterschiedliche Ergebnisse (" + "; ".join(result_label(r) for r in outcomes) + "). Die Einzelangaben nennen die jeweiligen prüfenden Systeme."})
        else:
            summary.append({"level": "warning" if outcomes[0] in ("fail", "softfail") else "info" if outcomes[0] == "pass" else "notice",
                            "text": (method.upper() + ": " + result_label(outcomes[0]) + ". " + SUMMARY_TEXT.get((method, outcomes[0]), "")).strip()})
    dmarc_domains = {r["properties"].get("header.from", "").lower().rstrip(".") for r in records if r["method"] == "dmarc"} - {""}
    if sender_domain and any(domain != sender_domain for domain in dmarc_domains):
        warning = "Die DMARC-Ergebnisse nennen als From-Domain " + ", ".join(sorted(dmarc_domains)) + "; im sichtbaren From-Feld steht " + sender_domain + ". Die Ergebnisse sind deshalb anhand der jeweiligen Domainangaben einzuordnen."
        rows.append(["Abweichende Domainangaben", warning])
        summary = [item for item in summary if not item["text"].startswith("DMARC:")]
        summary.append({"level": "warning", "text": warning})
    dmarc_outcomes = {r["result"] for r in records if r["method"] == "dmarc"}
    failures = any(r["result"] in ("fail", "softfail") for r in records)
    if len(dmarc_outcomes) > 1:
        rows.append(["Einordnung für die weitere Untersuchung", "Für DMARC liegen unterschiedliche Ergebnisse vor. Prüfsysteme, Domains und Transportstationen sind in den Einzelangaben getrennt aufgeführt; die Ergebnisse werden nicht zu einer einheitlichen Bestätigung zusammengefasst."])
    elif dmarc_outcomes == {"pass"}:
        rows.append(["Einordnung für die weitere Untersuchung", "DMARC meldet einen zur angegebenen From-Domain passenden Versandweg. Dafür genügt eine passende erfolgreiche SPF- oder DKIM-Prüfung. So kann DMARC auch bei einem SPF-Fehler durch eine passende DKIM-Signatur bestanden sein, etwa nach einer Weiterleitung."])
    elif failures:
        rows.append(["Einordnung für die weitere Untersuchung", "Fehlgeschlagene Absenderprüfungen können auf eine Absenderfälschung (Spoofing) hinweisen. Auch Weiterleitungen oder fehlerhafte Einstellungen können solche Ergebnisse verursachen. Die oben genannten Domains zeigen, auf welche Absenderidentität sich die jeweilige Prüfung bezieht."])
    elif any(r["result"] == "pass" for r in records):
        rows.append(["Einordnung für die weitere Untersuchung", "Bestandene Prüfungen dokumentieren eine Versandberechtigung oder Signatur für die jeweils geprüfte Domain. Für die Zuordnung zur sichtbaren Absenderdomain ist insbesondere das DMARC-Ergebnis maßgeblich."])
    else:
        rows.append(["Einordnung für die weitere Untersuchung", "Die Angaben reichen nicht aus, um zwischen einem zugelassenen Versandweg und einer Absenderfälschung (Spoofing) zu unterscheiden. Ein fehlendes Prüfergebnis ist kein Beleg für Spoofing."])
    section(report, "Authentifizierung laut Header", rows, status="ok" if records else "unavailable",
            source="Authentication-Results und Received-SPF")
    technical = []
    for index, value in enumerate(msg.get_all("ARC-Authentication-Results", [])[:30], 1):
        technical.append([f"Weitergereichte Prüfergebnisse / ARC #{index}", str(value)])
    for index, value in enumerate(msg.get_all("DKIM-Signature", [])[:30], 1):
        tags = assignments(value)
        technical.append([f"DKIM-Signatur #{index}", f"Signaturdomain: {tags.get('d', 'nicht angegeben')}; Selektor: {tags.get('s', 'nicht angegeben')}; Algorithmus: {tags.get('a', 'nicht angegeben')}. Ein Signaturfeld allein enthält noch kein Prüfergebnis."])
    if technical:
        section(report, "Signaturen und weitergereichte Prüfergebnisse", technical,
                note="ARC hält Prüfergebnisse früherer Transportstationen fest; diese werden getrennt von den oben ausgewerteten Ergebnissen geführt." if msg.get_all("ARC-Authentication-Results") else "", source="DKIM-Signature und ARC-Authentication-Results")
    return summary, records
