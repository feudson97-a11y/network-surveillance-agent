"""
web/app.py — Application Flask
================================
Serveur web principal avec toutes les routes du dashboard.
Lance avec : python main.py
"""

import os
import sys
import json
import threading
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_file, redirect, url_for

# Ajouter le dossier racine au path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from dotenv import load_dotenv
load_dotenv()

from app.database import (
    init_database, create_scan, finish_scan, save_device,
    save_analysis, save_alert, save_report, get_scans, get_scan,
    get_devices, get_analysis, get_alerts, get_reports,
    get_global_stats, get_latest_scan, get_unacknowledged_alerts
)
from app.scanner import scan_network
from app.analyzer import analyze_all_devices, calculate_risk
from app.ai_agent import run_crewai_analysis
from app.reporter import generate_reports
from app.utils import get_local_ip, get_network_range, validate_network_range, calculate_global_score, format_timestamp, risk_to_color, risk_to_emoji

app = Flask(__name__, template_folder="templates", static_folder="static")

# Scan en cours (pour éviter les doublons)
scan_running = False
current_scan_id = None


# ── Filtres Jinja2 ─────────────────────────────────────────

@app.template_filter("format_ts")
def format_ts_filter(value):
    return format_timestamp(value) if value else "—"

@app.template_filter("risk_color")
def risk_color_filter(value):
    return risk_to_color(value)

@app.template_filter("risk_emoji")
def risk_emoji_filter(value):
    return risk_to_emoji(value)

@app.template_filter("from_json")
def from_json_filter(value):
    try:
        return json.loads(value) if isinstance(value, str) else value
    except Exception:
        return []


# ── Routes principales ─────────────────────────────────────

@app.route("/")
def index():
    """Dashboard principal."""
    stats = get_global_stats()
    latest_scan = get_latest_scan()
    devices = []
    alerts = get_unacknowledged_alerts()[:5]
    recent_scans = get_scans(limit=5)

    if latest_scan:
        devices = get_devices(latest_scan["id"])[:10]

    return render_template("index.html",
        stats=stats,
        latest_scan=latest_scan,
        devices=devices,
        alerts=alerts,
        recent_scans=recent_scans,
        local_ip=get_local_ip(),
        network_range=os.getenv("NETWORK_RANGE") or get_network_range(),
    )


@app.route("/devices")
def devices_page():
    """Page des appareils détectés."""
    scan_id = request.args.get("scan_id", type=int)
    if not scan_id:
        latest = get_latest_scan()
        if latest:
            scan_id = latest["id"]

    devices = []
    scan = None
    if scan_id:
        devices = get_devices(scan_id)
        scan = get_scan(scan_id)
        # Enrichir avec analyses
        for d in devices:
            a = get_analysis(d["id"])
            if a:
                d["explanation"] = a.get("explanation", "")
                d["recommendations"] = a.get("recommendations", [])

    scans = get_scans(limit=10)
    return render_template("devices.html",
        devices=devices,
        scan=scan,
        scans=scans,
        selected_scan_id=scan_id,
    )


@app.route("/reports")
def reports_page():
    """Page des rapports générés."""
    reports = get_reports(limit=20)
    scans = get_scans(limit=10)
    return render_template("reports.html", reports=reports, scans=scans)


# ── API Routes ─────────────────────────────────────────────

@app.route("/api/scan/start", methods=["POST"])
def api_start_scan():
    """Lance un scan réseau complet."""
    global scan_running, current_scan_id

    if scan_running:
        return jsonify({"error": "Un scan est déjà en cours", "scan_id": current_scan_id}), 409

    data = request.get_json(silent=True) or {}
    network_range = data.get("network_range") or os.getenv("NETWORK_RANGE") or get_network_range()

    # Validation sécurité
    if not validate_network_range(network_range):
        return jsonify({"error": "Plage réseau invalide — uniquement les réseaux locaux sont autorisés"}), 400

    scan_id = create_scan(network_range)
    current_scan_id = scan_id
    scan_running = True

    def run_scan():
        global scan_running, current_scan_id
        try:
            # 1. Scanner le réseau
            devices_raw = scan_network(network_range)

            # 2. Analyser avec IA
            devices_analyzed = analyze_all_devices(devices_raw)

            # 3. Sauvegarder en DB
            device_ids = []
            for device in devices_analyzed:
                risk = calculate_risk(device)
                device.update(risk)
                dev_id = save_device(scan_id, device)
                device_ids.append(dev_id)
                save_analysis(dev_id, scan_id, {
                    "risk_level": device.get("risk_level", "low"),
                    "risk_score": device.get("risk_score", 0),
                    "explanation": device.get("explanation", ""),
                    "recommendations": device.get("recommendations", []),
                })
                # Alertes pour risques élevés
                if device.get("risk_level") == "high":
                    save_alert(
                        scan_id, device["ip"],
                        "HIGH_RISK_DEVICE",
                        f"Appareil à risque élevé détecté : {device['ip']} ({device['hostname']})",
                        "high"
                    )
                # Alertes pour ports dangereux
                for port_info in device.get("open_ports", []):
                    port = port_info.get("port") if isinstance(port_info, dict) else port_info
                    if port in [23, 21, 3306, 5432]:
                        save_alert(
                            scan_id, device["ip"],
                            "DANGEROUS_PORT",
                            f"Port dangereux {port} ouvert sur {device['ip']}",
                            "high"
                        )

            # 4. Analyse CrewAI globale
            high = sum(1 for d in devices_analyzed if d.get("risk_level") == "high")
            medium = sum(1 for d in devices_analyzed if d.get("risk_level") == "medium")
            global_score = calculate_global_score(devices_analyzed)

            scan_summary = {
                "total_devices": len(devices_analyzed),
                "high_risk": high,
                "medium_risk": medium,
                "low_risk": len(devices_analyzed) - high - medium,
                "global_score": global_score,
            }
            crew_analysis = run_crewai_analysis(devices_analyzed, scan_summary)

            # 5. Finaliser le scan
            finish_scan(scan_id, {**scan_summary, "global_score": global_score})

            # 6. Générer les rapports
            scan_info = get_scan(scan_id) or {}
            report_paths = generate_reports(scan_id, devices_analyzed, crew_analysis, scan_info)
            if report_paths.get("json"):
                save_report(scan_id, "json", report_paths["json"])
            if report_paths.get("pdf"):
                save_report(scan_id, "pdf", report_paths["pdf"])

            print(f"\n✅ Scan #{scan_id} terminé — {len(devices_analyzed)} appareil(s)")

        except Exception as e:
            print(f"❌ Erreur scan : {e}")
        finally:
            scan_running = False

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()

    return jsonify({
        "message": "Scan démarré",
        "scan_id": scan_id,
        "network_range": network_range,
    })


@app.route("/api/scan/status")
def api_scan_status():
    """Retourne le statut du scan en cours."""
    return jsonify({
        "running": scan_running,
        "scan_id": current_scan_id,
    })


@app.route("/api/scan/<int:scan_id>")
def api_get_scan(scan_id):
    """Retourne les données complètes d'un scan."""
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan non trouvé"}), 404
    devices = get_devices(scan_id)
    alerts = get_alerts(scan_id)
    return jsonify({"scan": scan, "devices": devices, "alerts": alerts})


@app.route("/api/stats")
def api_stats():
    """Retourne les statistiques globales."""
    return jsonify(get_global_stats())


@app.route("/api/alerts")
def api_alerts():
    """Retourne les alertes non acquittées."""
    return jsonify(get_unacknowledged_alerts())


@app.route("/api/download/<int:report_id>")
def api_download_report(report_id):
    """Télécharge un rapport."""
    from app.database import get_connection
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    if not row:
        return jsonify({"error": "Rapport non trouvé"}), 404
    path = dict(row)["file_path"]
    if not os.path.exists(path):
        return jsonify({"error": "Fichier introuvable"}), 404
    return send_file(path, as_attachment=True)


# ── Surveillance continue ──────────────────────────────────

def start_continuous_surveillance():
    """Lance la surveillance continue en arrière-plan."""
    import time
    interval = int(os.getenv("SCAN_INTERVAL", "300"))
    print(f"🔄 Surveillance continue activée (toutes les {interval}s)")

    def loop():
        while True:
            time.sleep(interval)
            if not scan_running:
                print(f"\n🔄 Scan automatique — {datetime.now().strftime('%H:%M:%S')}")
                with app.test_client() as client:
                    client.post("/api/scan/start", json={})

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()


if __name__ == "__main__":
    init_database()
    port = int(os.getenv("FLASK_PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    app.run(host="localhost", port=port, debug=debug)
