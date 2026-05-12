"""
app/utils.py — Utilitaires communs
=====================================
Fonctions partagées entre les modules.
"""

import socket
import subprocess
import platform
import os
import ipaddress
from datetime import datetime


def get_local_ip() -> str:
    """Détecte l'IP locale de la machine."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def get_network_range(local_ip: str = None) -> str:
    """Calcule la plage réseau /24 à partir de l'IP locale."""
    ip = local_ip or get_local_ip()
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def validate_network_range(network_range: str) -> bool:
    """Valide qu'une plage réseau est locale (sécurité)."""
    try:
        network = ipaddress.IPv4Network(network_range, strict=False)
        # Autoriser uniquement les plages privées
        private_ranges = [
            ipaddress.IPv4Network("10.0.0.0/8"),
            ipaddress.IPv4Network("172.16.0.0/12"),
            ipaddress.IPv4Network("192.168.0.0/16"),
        ]
        return any(network.subnet_of(r) for r in private_ranges)
    except Exception:
        return False


def ping_host(ip: str, timeout: int = 1) -> bool:
    """Vérifie si un hôte répond au ping."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), str(ip)]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), str(ip)]
    try:
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout + 1)
        return result.returncode == 0
    except Exception:
        return False


def get_hostname(ip: str) -> str:
    """Résout le nom d'hôte depuis l'IP."""
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except Exception:
        return "Inconnu"


def format_timestamp(iso_string: str) -> str:
    """Formate un timestamp ISO en format lisible."""
    try:
        dt = datetime.fromisoformat(iso_string)
        return dt.strftime("%d/%m/%Y %H:%M:%S")
    except Exception:
        return iso_string


def risk_to_color(risk_level: str) -> str:
    """Retourne la couleur Bootstrap associée au niveau de risque."""
    return {
        "high": "danger",
        "medium": "warning",
        "low": "success",
    }.get(risk_level, "secondary")


def risk_to_emoji(risk_level: str) -> str:
    """Retourne l'emoji associé au niveau de risque."""
    return {
        "high": "🔴",
        "medium": "🟡",
        "low": "🟢",
    }.get(risk_level, "⚪")


def calculate_global_score(devices: list) -> int:
    """Calcule le score de risque global (0-100) depuis la liste des appareils."""
    if not devices:
        return 0
    total_score = sum(d.get("risk_score", 0) for d in devices)
    max_possible = len(devices) * 10
    return min(100, int((total_score / max_possible) * 100)) if max_possible > 0 else 0
