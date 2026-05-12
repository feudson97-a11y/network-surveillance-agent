"""
app/reporter.py — Génération de rapports PDF et JSON
======================================================
Génère des rapports professionnels en deux formats :
- JSON : données brutes structurées
- PDF  : rapport visuel avec ReportLab
"""

import os
import json
from datetime import datetime

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")


def ensure_reports_dir():
    os.makedirs(REPORTS_DIR, exist_ok=True)


def generate_json_report(scan_id: int, devices: list, analysis: dict, scan_info: dict) -> str:
    """Génère un rapport JSON complet."""
    ensure_reports_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_scan{scan_id}_{timestamp}.json"
    filepath = os.path.join(REPORTS_DIR, filename)

    report = {
        "metadata": {
            "report_id": f"NSA-{scan_id}-{timestamp}",
            "generated_at": datetime.now().isoformat(),
            "scan_id": scan_id,
            "tool": "Network Surveillance Agent v2.0",
        },
        "scan_summary": {
            "network_range": scan_info.get("network_range", "N/A"),
            "started_at": scan_info.get("started_at", ""),
            "finished_at": scan_info.get("finished_at", ""),
            "total_devices": len(devices),
            "high_risk": sum(1 for d in devices if d.get("risk_level") == "high"),
            "medium_risk": sum(1 for d in devices if d.get("risk_level") == "medium"),
            "low_risk": sum(1 for d in devices if d.get("risk_level") == "low"),
            "global_score": scan_info.get("global_score", 0),
        },
        "devices": [
            {
                "ip": d.get("ip"),
                "hostname": d.get("hostname"),
                "mac": d.get("mac"),
                "vendor": d.get("vendor"),
                "open_ports": d.get("open_ports", []),
                "risk_level": d.get("risk_level"),
                "risk_score": d.get("risk_score"),
                "explanation": d.get("explanation", ""),
                "recommendations": d.get("recommendations", []),
            }
            for d in devices
        ],
        "ai_analysis": {
            "crew_report": analysis.get("crew_report", ""),
            "ai_powered": analysis.get("ai_powered", False),
            "agents_used": analysis.get("agents_used", []),
        },
        "legal_notice": "Ce rapport concerne uniquement le réseau local autorisé. Scanner un réseau sans autorisation est illégal.",
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"✅ Rapport JSON : {filename}")
    return filepath


def generate_pdf_report(scan_id: int, devices: list, analysis: dict, scan_info: dict) -> str:
    """Génère un rapport PDF professionnel."""
    ensure_reports_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_scan{scan_id}_{timestamp}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.colors import HexColor, black, white
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table,
            TableStyle, HRFlowable
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT

        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm
        )

        # Couleurs
        DARK_BG   = HexColor("#0a0e1a")
        BLUE      = HexColor("#1565c0")
        RED       = HexColor("#c62828")
        ORANGE    = HexColor("#e65100")
        GREEN_C   = HexColor("#2e7d32")
        GRAY      = HexColor("#424242")
        LIGHT_BG  = HexColor("#f5f5f5")

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle("Title", parent=styles["Title"],
            fontSize=22, textColor=BLUE, spaceAfter=6, alignment=TA_CENTER)
        subtitle_style = ParagraphStyle("Subtitle", parent=styles["Normal"],
            fontSize=11, textColor=GRAY, spaceAfter=20, alignment=TA_CENTER)
        h2_style = ParagraphStyle("H2", parent=styles["Heading2"],
            fontSize=14, textColor=BLUE, spaceBefore=16, spaceAfter=8)
        body_style = ParagraphStyle("Body", parent=styles["Normal"],
            fontSize=10, textColor=black, spaceAfter=6, leading=14)
        code_style = ParagraphStyle("Code", parent=styles["Normal"],
            fontSize=9, textColor=GRAY, fontName="Courier", spaceAfter=4)

        story = []

        # ── En-tête ───────────────────────────────────────────
        story.append(Paragraph("🛡️ Network Surveillance Agent", title_style))
        story.append(Paragraph("Rapport de Sécurité Réseau", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=2, color=BLUE))
        story.append(Spacer(1, 0.5*cm))

        # ── Méta-informations ──────────────────────────────────
        meta_data = [
            ["Rapport ID", f"NSA-{scan_id}-{timestamp}"],
            ["Date", datetime.now().strftime("%d/%m/%Y %H:%M:%S")],
            ["Réseau analysé", scan_info.get("network_range", "N/A")],
            ["Durée du scan", f"{scan_info.get('started_at', '')} → {scan_info.get('finished_at', '')}"],
        ]
        meta_table = Table(meta_data, colWidths=[4*cm, 13*cm])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), LIGHT_BG),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.5*cm))

        # ── Résumé ─────────────────────────────────────────────
        story.append(Paragraph("Résumé du Scan", h2_style))
        high = sum(1 for d in devices if d.get("risk_level") == "high")
        medium = sum(1 for d in devices if d.get("risk_level") == "medium")
        low = len(devices) - high - medium

        summary_data = [
            ["Métrique", "Valeur", "Statut"],
            ["Appareils détectés", str(len(devices)), "—"],
            ["Risque élevé 🔴", str(high), "CRITIQUE" if high > 0 else "OK"],
            ["Risque moyen 🟡", str(medium), "ATTENTION" if medium > 0 else "OK"],
            ["Risque faible 🟢", str(low), "OK"],
            ["Score global", f"{scan_info.get('global_score', 0)}/100", ""],
        ]
        summary_table = Table(summary_data, colWidths=[7*cm, 4*cm, 6*cm])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, LIGHT_BG]),
            ("TEXTCOLOR", (2, 2), (2, 2), RED if high > 0 else GREEN_C),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.5*cm))

        # ── Appareils détectés ─────────────────────────────────
        story.append(Paragraph("Appareils Détectés", h2_style))
        dev_data = [["IP", "Hostname", "MAC", "Ports", "Risque"]]
        for d in sorted(devices, key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x.get("risk_level"), 3)):
            ports = ", ".join(str(p.get("port", p)) for p in d.get("open_ports", [])[:4])
            risk = d.get("risk_level", "low").upper()
            dev_data.append([
                d.get("ip", ""),
                d.get("hostname", "")[:20],
                d.get("mac", "")[:17],
                ports or "Aucun",
                risk,
            ])

        dev_table = Table(dev_data, colWidths=[3.5*cm, 4*cm, 3.5*cm, 3.5*cm, 2.5*cm])
        dev_style = [
            ("BACKGROUND", (0, 0), (-1, 0), BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, LIGHT_BG]),
        ]
        for i, d in enumerate(devices, start=1):
            risk = d.get("risk_level", "low")
            if risk == "high":
                dev_style.append(("TEXTCOLOR", (4, i), (4, i), RED))
                dev_style.append(("FONTNAME", (4, i), (4, i), "Helvetica-Bold"))
            elif risk == "medium":
                dev_style.append(("TEXTCOLOR", (4, i), (4, i), ORANGE))

        dev_table.setStyle(TableStyle(dev_style))
        story.append(dev_table)
        story.append(Spacer(1, 0.5*cm))

        # ── Analyse IA ─────────────────────────────────────────
        story.append(Paragraph("Analyse IA — Rapport SOC", h2_style))
        crew_report = analysis.get("crew_report", "Aucune analyse disponible.")
        for line in crew_report.split("\n"):
            line = line.strip()
            if not line:
                story.append(Spacer(1, 0.2*cm))
            elif line.startswith("##"):
                story.append(Paragraph(line.replace("##", "").strip(), h2_style))
            else:
                story.append(Paragraph(line, body_style))

        # ── Notice légale ──────────────────────────────────────
        story.append(Spacer(1, 1*cm))
        story.append(HRFlowable(width="100%", thickness=1, color=GRAY))
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph(
            "⚠️ AVERTISSEMENT LÉGAL : Ce rapport concerne uniquement le réseau local autorisé. "
            "Scanner un réseau sans autorisation explicite est illégal.",
            ParagraphStyle("Legal", parent=styles["Normal"], fontSize=8, textColor=GRAY, alignment=TA_CENTER)
        ))

        doc.build(story)
        print(f"✅ Rapport PDF : {filename}")
        return filepath

    except ImportError:
        print("⚠️  ReportLab non installé — rapport PDF ignoré")
        return ""
    except Exception as e:
        print(f"⚠️  Erreur PDF : {e}")
        return ""


def generate_reports(scan_id: int, devices: list, analysis: dict, scan_info: dict) -> dict:
    """Génère les deux formats de rapports."""
    print("\n📄 Génération des rapports...")
    json_path = generate_json_report(scan_id, devices, analysis, scan_info)
    pdf_path = generate_pdf_report(scan_id, devices, analysis, scan_info)
    return {"json": json_path, "pdf": pdf_path}
