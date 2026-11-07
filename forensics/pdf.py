"""Neutral, in-memory A4 report. No temporary documents or remote resources."""
import io
import re
from pathlib import Path
from xml.sax.saxutils import escape

import reportlab
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import HRFlowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer

REPOSITORY_URL = "https://github.com/gl1tchb1rd/web_forensics"

FONT_DIR = Path(reportlab.__file__).parent / "fonts"
pdfmetrics.registerFont(TTFont("WF", str(FONT_DIR / "Vera.ttf")))
pdfmetrics.registerFont(TTFont("WF-Bold", str(FONT_DIR / "VeraBd.ttf")))
pdfmetrics.registerFontFamily("WF", normal="WF", bold="WF-Bold", italic="WF", boldItalic="WF-Bold")


def safe(value):
    return escape(re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "�", str(value)))


def render_pdf(report):
    output = io.BytesIO()
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("BodyWF", fontName="WF", fontSize=9, leading=13, spaceAfter=6, wordWrap="CJK"))
    styles.add(ParagraphStyle("SmallWF", parent=styles["BodyWF"], fontSize=7.5, leading=10, textColor=colors.HexColor("#444444")))
    styles.add(ParagraphStyle("SectionMetaWF", parent=styles["SmallWF"], keepWithNext=True))
    styles.add(ParagraphStyle("SectionNoteWF", parent=styles["BodyWF"], keepWithNext=True))
    styles.add(ParagraphStyle("TitleWF", fontName="WF-Bold", fontSize=23, leading=29, spaceAfter=8))
    styles.add(ParagraphStyle("HeadingWF", fontName="WF-Bold", fontSize=12, leading=17, spaceBefore=14, spaceAfter=8, keepWithNext=True))
    styles.add(ParagraphStyle("RawWF", parent=styles["SmallWF"], fontSize=7, leading=10, alignment=TA_LEFT, spaceAfter=1))
    document = SimpleDocTemplate(output, pagesize=A4, rightMargin=22 * mm, leftMargin=22 * mm, topMargin=34 * mm, bottomMargin=24 * mm,
                                 title="Web Forensics – Untersuchungsbericht", author="Web Forensics", subject="Technischer Analysebericht", pageCompression=1)
    story = []

    def p(value, style="BodyWF"):
        return Paragraph(safe(value).replace("\n", "<br/>"), styles[style])

    def heading(value):
        story.append(p(value, "HeadingWF"))

    def frame(canvas, doc):
        canvas.saveState()
        canvas.setFont("WF-Bold", 8)
        canvas.drawString(22 * mm, 285 * mm, "WEB FORENSICS · TECHNISCHER BERICHT")
        case_style = ParagraphStyle("CaseHeader", fontName="WF", fontSize=7, leading=9, wordWrap="CJK")
        label = Paragraph("Aktenzeichen: " + safe(report["case"]), case_style)
        _, height = label.wrap(166 * mm, 15 * mm)
        label.drawOn(canvas, 22 * mm, 278 * mm - height)
        canvas.setStrokeColor(colors.HexColor("#cccccc"))
        canvas.line(22 * mm, 268 * mm, 188 * mm, 268 * mm)
        canvas.line(22 * mm, 19 * mm, 188 * mm, 19 * mm)
        canvas.setFont("WF", 7)
        canvas.drawString(22 * mm, 14 * mm, "Analyse-ID: " + report["id"])
        canvas.drawRightString(188 * mm, 14 * mm, f"Seite {doc.page}")
        canvas.restoreState()

    title = "Domainanalyse" if report["module"] == "domain" else "E-Mail-Header-Analyse"
    story += [p("Untersuchungsbericht", "TitleWF"), p(title, "HeadingWF"), Spacer(1, 4 * mm)]
    for label, value in (("Aktenzeichen", report["case"]), ("Untersuchungsgegenstand", report["target"]), ("Analyse-ID", report["id"]),
                         ("Beginn (UTC)", report["started_at"]), ("Abschluss (UTC)", report["finished_at"]), ("Software", "Web Forensics " + report["version"]),
                         ("SHA-256 der Eingabe", report["input_sha256"])):
        story.append(Paragraph(f"<b>{safe(label)}:</b> {safe(value)}", styles["BodyWF"]))
    story.append(Paragraph(f'<b>Programm-Repository:</b> <link href="{REPOSITORY_URL}" color="#222222">{REPOSITORY_URL}</link>', styles["SmallWF"]))
    story += [p(report["hash_note"], "SmallWF"), HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#bbbbbb"))]
    heading("1. Wesentliche Feststellungen")
    for item in report["summary"]:
        label = {"warning": "Auffälligkeit", "notice": "Hinweis", "info": "Feststellung"}.get(item["level"], "Hinweis")
        story.append(p(f"{label}: {item['text']}"))
    heading("2. Grundlage und Einordnung" if report["module"] == "headers" else "2. Prüfverfahren und Aussagegrenzen")
    for limitation in report["limitations"]:
        story.append(p("• " + limitation))
    heading("3. Einzelergebnisse")
    status_names = {"ok": "Ergebnis vorhanden", "empty": "Kein Eintrag", "unavailable": "Nicht verfügbar / nicht prüfbar"}
    for index, item in enumerate(report["sections"], 1):
        if item["title"] == "Übermittelter Originalheader":
            continue
        heading(f"3.{index} {item['title']}")
        meta_style = "SectionMetaWF" if item["rows"] else "SmallWF"
        story.append(p("Prüfstatus: " + status_names.get(item["status"], item["status"]), meta_style))
        if item["source"]:
            story.append(p("Quelle: " + item["source"], meta_style))
        if item["note"]:
            story.append(p(item["note"], "SectionNoteWF" if item["rows"] else "BodyWF"))
        for label, value in item["rows"]:
            story.append(Paragraph(f"<b>{safe(label)}</b><br/>{safe(value).replace(chr(10), '<br/>')}", styles["BodyWF"]))
    heading("4. Datenquellen und externe Abfragen")
    for source in report["sources"]:
        story.append(p(source, "SmallWF"))
    for purpose, recipient, transmitted in report.get("disclosure", []):
        story.append(p(f"{purpose}: {recipient}\nÜbermittelte Daten: {transmitted}", "SmallWF"))
    story.append(p("Dieser Bericht dokumentiert technische Beobachtungen. Er enthält keine abschließende rechtliche Bewertung und ist nicht digital signiert.", "SmallWF"))
    raw_sections = [s for s in report["sections"] if s["raw"]]
    if raw_sections:
        story.append(PageBreak())
        heading("5. Anlagen / Rohdaten")
        for item in raw_sections:
            heading(item["title"])
            raw = item["raw"]
            if report["module"] == "domain" and len(raw) > 16384:
                raw = raw[:16384]
                story.append(p("Rohdaten-Auszug: auf 16.384 Zeichen begrenzt. Die im Ergebnis angegebene Prüfsumme bezieht sich auf die vollständige empfangene Antwort.", "SmallWF"))
            # Individual, bounded lines allow pagination even for oversized header fields.
            for line in raw.splitlines():
                pieces = [line[i:i + 180] for i in range(0, len(line), 180)] or [" "]
                story.extend(p(part, "RawWF") for part in pieces)
    document.build(story, onFirstPage=frame, onLaterPages=frame)
    return output.getvalue()
