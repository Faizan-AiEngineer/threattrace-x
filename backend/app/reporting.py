import csv
import io
import json
from html import escape
from pathlib import Path

import reportlab
from fastapi import HTTPException
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate
from sqlalchemy import func, select

from . import analysis, db, vault
from .settings import CASE_EVENT_LIMIT

MIME = {
    "html": "text/html",
    "pdf": "application/pdf",
    "json": "application/json",
    "events.csv": "text/csv",
    "findings.csv": "text/csv",
}
PRESENTATION_LIMIT = 200
FONT_DIRECTORY = Path(reportlab.__file__).with_name("fonts")
pdfmetrics.registerFont(TTFont("InvestigationSans", str(FONT_DIRECTORY / "Vera.ttf")))
pdfmetrics.registerFont(
    TTFont("InvestigationSans-Bold", str(FONT_DIRECTORY / "VeraBd.ttf"))
)


def snapshot(connection, case):
    case_id = case["id"]
    event_count = connection.scalar(
        select(func.count())
        .select_from(db.events)
        .where(db.events.c.case_id == case_id)
    )
    if event_count > CASE_EVENT_LIMIT:
        raise HTTPException(
            422,
            f"Report generation supports up to {CASE_EVENT_LIMIT:,} events per case",
        )
    items = analysis.items(connection, db.evidence, case_id)
    chronology = sorted(
        analysis.items(connection, db.events, case_id), key=analysis.event_order
    )
    findings = [
        analysis.enrich_finding(connection, row)
        for row in analysis.items(
            connection, db.findings, case_id, db.findings.c.active.is_(True)
        )
    ]
    findings.sort(key=lambda row: (row["timestamp"] or "", row["id"]))
    return {
        "case": case,
        "generated_at": db.utc(),
        "evidence": items,
        "custody": [
            {
                "id": row["id"],
                "filename": row["filename"],
                **vault.custody_verify(connection, row),
            }
            for row in items
        ],
        "timeline": chronology,
        "findings": findings,
        "notes": analysis.items(connection, db.notes, case_id),
        "network": analysis.network(
            [row for row in chronology if row["category"] == "network"]
        ),
        "matches": [
            dict(row)
            for row in connection.execute(
                select(
                    db.matches.c.event_id,
                    db.indicators.c.value,
                    db.indicators.c.source,
                    db.indicators.c.confidence,
                )
                .join(db.indicators, db.indicators.c.id == db.matches.c.indicator_id)
                .where(db.matches.c.case_id == case_id)
            ).mappings()
        ],
        "limitations": [
            "Case scope is limited to imported records. Uncertain timestamps are listed separately at the end.",
            "Integrity states reflect recorded verification. Results reflect the last analysis run.",
            "Correlation and ATT&CK associations are investigative leads. Confidence scores are heuristic.",
            f"HTML and PDF each show up to {PRESENTATION_LIMIT} entries per section. Use JSON or CSV for full records.",
        ],
    }


def summary_lines(data):
    case = data["case"]
    return [
        (
            "Case identification",
            [
                f"{case['id']} · {case['classification']} · {case['status']}",
                f"Investigator {case['investigator']} · Severity {case['severity']}",
                f"Generated {data['generated_at']} UTC",
            ]
            + (["Synthetic demonstration"] if case["synthetic"] else []),
        ),
        (
            "Executive summary",
            [
                (
                    f"{len(data['evidence'])} evidence items, {len(data['timeline'])} events, "
                    f"{len(data['findings'])} current findings."
                )
            ],
        ),
        ("Scope", [case["description"] or "No narrative scope recorded."]),
        (
            "Methodology",
            [
                (
                    "Preserved bytes and SHA-256 inventory, source-anchored normalization, local rule and indicator "
                    "evaluation, and time-window correlation."
                )
            ],
        ),
        (
            "Evidence inventory and integrity",
            [
                f"{e['filename']} · {e['integrity']} · {e['size']} bytes · evidence {e['id']} · SHA-256 {e['sha256']} "
                f"· source {e['source']} · parser {e['parser_version']} · {e['stats']['parsed']} parsed, "
                f"{e['stats']['malformed']} malformed"
                for e in data["evidence"]
            ],
        ),
        (
            "Chain of custody",
            [
                f"{e['filename']} · {e['records']} records · {'valid' if e['valid'] else 'failed'}"
                for e in data["custody"]
            ],
        ),
        (
            "Incident timeline",
            [
                f"{r['timestamp'] or r['time_quality']} · {r['action']} · {r['hostname'] or 'host unknown'} "
                f"· {r['source_ref']} · evidence {r['evidence_id']}"
                for r in data["timeline"]
            ],
        ),
        (
            "Findings and confidence",
            [
                f"{r['name']} · {r['stage']} · {r['severity']} · score {r['confidence']['score']} "
                f"· {r['explanation']} · evidence {', '.join(r['evidence_ids'])}"
                f" · {len(r['event_ids'])} supporting events"
                + (
                    f" · analyst override {r['override']}: {r['review_reason']}"
                    if r["override"] is not None
                    else ""
                )
                for r in data["findings"]
            ],
        ),
        (
            "Network analysis",
            [
                f"{data['network']['records']} records · {data['network']['bytes']:,} reported bytes",
                ", ".join(f"{p}: {count}" for p, count in data["network"]["protocols"]),
            ],
        ),
        (
            "Threat intelligence",
            [
                f"{m['value']} · exact match · {m['source']} · event {m['event_id']}"
                for m in data["matches"]
            ],
        ),
        (
            "MITRE ATT&CK classifications",
            [
                f"{r['technique']} · rule association · {r['name']}"
                for r in data["findings"]
                if r["technique"]
            ],
        ),
        ("Limitations", data["limitations"]),
        (
            "Defensive recommendations",
            list(dict.fromkeys(r["steps"] for r in data["findings"])),
        ),
        (
            "Investigator notes",
            [f"{r['timestamp']} · {r['actor']} · {r['body']}" for r in data["notes"]],
        ),
    ]


def safe_csv(item):
    if isinstance(item, (dict, list)):
        item = json.dumps(item, ensure_ascii=False)
    if isinstance(item, str) and (
        item.lstrip().startswith(("=", "+", "-", "@"))
        or item.startswith(("\t", "\r", "\n"))
    ):
        return "'" + item
    return item


def csv_bytes(data, headers):
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(headers)
    writer.writerows([safe_csv(row.get(header)) for header in headers] for row in data)
    return output.getvalue().encode("utf-8-sig")


def html_report(data):
    title = escape(data["case"]["title"])
    sections = []
    for name, lines in summary_lines(data):
        if len(lines) > PRESENTATION_LIMIT:
            lines = [
                *lines[:PRESENTATION_LIMIT],
                f"{len(lines) - PRESENTATION_LIMIT} additional entries in JSON.",
            ]
        content = (
            "".join(f"<li>{escape(line)}</li>" for line in lines if line)
            or "<li>None recorded.</li>"
        )
        sections.append(f"<section><h2>{escape(name)}</h2><ul>{content}</ul></section>")
    return (
        f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
        f"<title>{title} | ThreatTrace X</title><style>"
        "body{max-width:900px;margin:48px auto;padding:0 24px;font:15px/1.65 system-ui;color:#203041}"
        "header{border-bottom:3px solid #167d87;padding-bottom:14px}small{color:#176f7b;letter-spacing:.13em}"
        "h1{font-size:33px;margin:6px 0}h2{font-size:18px;margin:0 0 6px}section{padding:15px 0;"
        "border-bottom:1px solid #d9e3eb}ul{padding-left:19px;margin:0;overflow-wrap:anywhere}"
        f"</style><header><small>THREATTRACE X / INVESTIGATION REPORT</small><h1>{title}</h1></header>"
        f"{''.join(sections)}</html>"
    ).encode()


def pdf_report(data):
    output = io.BytesIO()
    document = SimpleDocTemplate(
        output,
        title=data["case"]["title"],
        author="ThreatTrace X",
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
    )
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="InvestigationBody",
            fontName="InvestigationSans",
            fontSize=9,
            leading=13,
            spaceAfter=6,
            textColor=colors.HexColor("#26394b"),
            splitLongWords=True,
        )
    )
    styles["Title"].alignment = TA_LEFT
    styles["Title"].fontName = "InvestigationSans-Bold"
    styles["Heading2"].fontName = "InvestigationSans-Bold"
    styles["Heading2"].textColor = colors.HexColor("#167985")
    flow = [
        Paragraph("THREATTRACE X / INVESTIGATION REPORT", styles["InvestigationBody"]),
        Paragraph(escape(data["case"]["title"]), styles["Title"]),
    ]
    for name, lines in summary_lines(data):
        flow.append(Paragraph(escape(name), styles["Heading2"]))
        if len(lines) > PRESENTATION_LIMIT:
            lines = [
                *lines[:PRESENTATION_LIMIT],
                f"{len(lines) - PRESENTATION_LIMIT} additional entries in JSON.",
            ]
        flow.extend(
            Paragraph(escape(text), styles["InvestigationBody"])
            for text in (lines or ["None recorded."])
        )

    def footer(canvas, doc):
        canvas.setStrokeColor(colors.HexColor("#d9e3eb"))
        canvas.line(doc.leftMargin, 42, doc.pagesize[0] - doc.rightMargin, 42)
        canvas.setFillColor(colors.HexColor("#476275"))
        canvas.setFont("InvestigationSans", 8)
        canvas.drawString(doc.leftMargin, 30, "ThreatTrace X  /  Investigation report")
        canvas.drawRightString(
            doc.pagesize[0] - doc.rightMargin, 30, f"Page {doc.page}"
        )

    document.build(flow, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()


def render(data, format):
    if format == "events.csv":
        return csv_bytes(
            data["timeline"],
            (
                "id",
                "timestamp",
                "original_timestamp",
                "time_quality",
                "category",
                "action",
                "hostname",
                "username",
                "evidence_id",
                "source_ref",
            ),
        )
    if format == "findings.csv":
        return csv_bytes(
            data["findings"],
            (
                "id",
                "name",
                "rule_id",
                "severity",
                "stage",
                "confidence",
                "event_ids",
                "evidence_ids",
                "explanation",
                "review_reason",
            ),
        )
    if format == "json":
        return json.dumps(data, ensure_ascii=False, indent=2).encode()
    if format == "html":
        return html_report(data)
    return pdf_report(data)
