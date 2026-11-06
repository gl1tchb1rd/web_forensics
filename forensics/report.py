import hashlib
import re
import uuid
from datetime import datetime, timezone
from webforensics import __version__


def validate_case(value):
    if not isinstance(value, str):
        raise ValueError("Bitte ein Aktenzeichen angeben.")
    value = value.strip()
    if not value or len(value) > 100 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Das Aktenzeichen muss 1–100 Zeichen ohne Steuerzeichen enthalten.")
    return value


def new_report(module, case, target, original):
    return {
        "version": __version__, "id": str(uuid.uuid4()), "module": module,
        "case": validate_case(case), "target": target,
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "finished_at": None,
        "input_sha256": hashlib.sha256(original.encode("utf-8")).hexdigest(),
        "hash_note": "SHA-256 der übermittelten UTF-8-Eingabe; kein Nachweis der Echtheit oder eines ursprünglichen EML-Dateiinhalts.",
        "summary": [], "sections": [], "sources": [], "limitations": [],
    }


def section(report, title, rows, status="ok", note="", raw="", source=""):
    item = {"title": title, "status": status, "note": note, "rows": rows, "raw": raw, "source": source}
    report["sections"].append(item)
    return item


def finish(report):
    report["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return report


def filename(report):
    safe_case = re.sub(r"[^A-Za-z0-9._-]+", "_", report["case"]).strip("._")[:80] or "Aktenzeichen"
    module = "Domainanalyse" if report["module"] == "domain" else "Headeranalyse"
    return f"{safe_case}_{module}_{report['started_at'][:10]}_{report['id'][:8]}.pdf"
