"""
main.py — Point d'entrée principal
=====================================
Lance l'application avec :
    python main.py

Options :
    python main.py --continuous    Lance la surveillance continue
    python main.py --scan-only     Scan unique sans interface web
"""

import sys
import os
import webbrowser
import threading
import time

# S'assurer que le dossier racine est dans le path
sys.path.insert(0, os.path.dirname(__file__))

from dotenv import load_dotenv
load_dotenv()


def print_banner():
    print("""
╔══════════════════════════════════════════════════════╗
║       🛡️  NETWORK SURVEILLANCE AGENT v2.0            ║
║          Agent IA de Cybersécurité                   ║
║                                                      ║
║  Framework : CrewAI + OpenAI GPT-4o-mini             ║
║  Backend   : Flask + SQLite                          ║
║  Frontend  : Bootstrap 5 (dark theme)                ║
╚══════════════════════════════════════════════════════╝
    """)


def check_env():
    """Vérifie la configuration avant le démarrage."""
    print("📋 Vérification de la configuration...")

    api_key = os.getenv("OPENAI_API_KEY", "")
    if not api_key or api_key.startswith("sk-proj-xxx"):
        print("  ⚠️  OPENAI_API_KEY manquante — analyse IA désactivée")
        print("     Ajoute ta clé dans .env pour activer l'analyse complète")
    else:
        print("  ✅ OpenAI configuré")

    network = os.getenv("NETWORK_RANGE", "")
    if network:
        print(f"  ✅ Réseau configuré : {network}")
    else:
        from app.utils import get_local_ip, get_network_range
        auto_range = get_network_range(get_local_ip())
        print(f"  ℹ️  Réseau auto-détecté : {auto_range}")

    print()


def open_browser(port: int):
    """Ouvre le navigateur après 2 secondes."""
    time.sleep(2)
    webbrowser.open(f"http://localhost:{port}")


def run_web_server(continuous: bool = False):
    """Lance le serveur Flask."""
    from app.database import init_database
    from web.app import app, start_continuous_surveillance

    init_database()

    port = int(os.getenv("FLASK_PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "False").lower() == "true"

    if continuous:
        start_continuous_surveillance()
        print("🔄 Surveillance continue activée")

    print(f"🌐 Dashboard disponible sur : http://localhost:{port}")
    print("   Appuie sur CTRL+C pour arrêter\n")

    # Ouvrir le navigateur automatiquement
    browser_thread = threading.Thread(target=open_browser, args=(port,), daemon=True)
    browser_thread.start()

    app.run(host="localhost", port=port, debug=debug, use_reloader=False)


def run_scan_only():
    """Lance un scan unique sans interface web."""
    from app.database import init_database, create_scan, finish_scan, save_device, save_analysis
    from app.scanner import scan_network
    from app.analyzer import analyze_all_devices, calculate_risk
    from app.ai_agent import run_crewai_analysis
    from app.reporter import generate_reports
    from app.utils import get_local_ip, get_network_range, calculate_global_score

    init_database()

    network_range = os.getenv("NETWORK_RANGE") or get_network_range(get_local_ip())
    print(f"🎯 Réseau cible : {network_range}\n")

    scan_id = create_scan(network_range)
    devices_raw = scan_network(network_range)
    devices_analyzed = analyze_all_devices(devices_raw)

    for device in devices_analyzed:
        risk = calculate_risk(device)
        device.update(risk)
        dev_id = save_device(scan_id, device)
        save_analysis(dev_id, scan_id, device)

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
    finish_scan(scan_id, scan_summary)

    from app.database import get_scan
    scan_info = get_scan(scan_id) or {}
    report_paths = generate_reports(scan_id, devices_analyzed, crew_analysis, scan_info)

    print(f"\n{'='*50}")
    print(f"✅ Scan #{scan_id} terminé")
    print(f"   Appareils : {len(devices_analyzed)}")
    print(f"   Risque élevé : {high}")
    print(f"   Score global : {global_score}/100")
    if report_paths.get("json"):
        print(f"   Rapport JSON : {report_paths['json']}")
    if report_paths.get("pdf"):
        print(f"   Rapport PDF  : {report_paths['pdf']}")
    print(f"{'='*50}\n")


if __name__ == "__main__":
    print_banner()
    check_env()

    args = sys.argv[1:]

    if "--scan-only" in args:
        print("🔍 Mode scan unique (sans interface web)\n")
        run_scan_only()
    elif "--continuous" in args:
        print("🔄 Mode surveillance continue activé\n")
        run_web_server(continuous=True)
    else:
        print("🚀 Démarrage de l'interface web...\n")
        run_web_server(continuous=False)
