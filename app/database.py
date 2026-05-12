"""
app/database.py — Gestion SQLite
==================================
Gère toutes les opérations de base de données.
Stocke : scans, appareils, ports, analyses, rapports.
"""

import sqlite3
import os
import json
from datetime import datetime
from typing import Optional

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "database", "surveillance.db")


def get_connection() -> sqlite3.Connection:
    """Retourne une connexion SQLite avec row_factory pour les dicts."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_database() -> None:
    """Initialise la base de données et crée les tables si elles n'existent pas."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    with get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                network_range TEXT,
                total_devices INTEGER DEFAULT 0,
                high_risk INTEGER DEFAULT 0,
                medium_risk INTEGER DEFAULT 0,
                low_risk INTEGER DEFAULT 0,
                global_score INTEGER DEFAULT 0,
                status TEXT DEFAULT 'running'
            );

            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                mac TEXT DEFAULT 'Inconnu',
                hostname TEXT DEFAULT 'Inconnu',
                vendor TEXT DEFAULT 'Inconnu',
                open_ports TEXT DEFAULT '[]',
                risk_level TEXT DEFAULT 'low',
                risk_score INTEGER DEFAULT 0,
                detected_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                scan_id INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                explanation TEXT,
                recommendations TEXT,
                analyzed_at TEXT NOT NULL,
                FOREIGN KEY (device_id) REFERENCES devices(id),
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                device_ip TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                message TEXT NOT NULL,
                severity TEXT DEFAULT 'medium',
                created_at TEXT NOT NULL,
                acknowledged INTEGER DEFAULT 0,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                format TEXT NOT NULL,
                file_path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
        """)
    print("✅ Base de données initialisée")


# ── Scans ──────────────────────────────────────────────────

def create_scan(network_range: str) -> int:
    """Crée un nouveau scan et retourne son ID."""
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO scans (started_at, network_range, status) VALUES (?, ?, 'running')",
            (datetime.now().isoformat(), network_range)
        )
        return cur.lastrowid


def finish_scan(scan_id: int, stats: dict) -> None:
    """Met à jour le scan avec les statistiques finales."""
    with get_connection() as conn:
        conn.execute("""
            UPDATE scans SET
                finished_at = ?,
                total_devices = ?,
                high_risk = ?,
                medium_risk = ?,
                low_risk = ?,
                global_score = ?,
                status = 'completed'
            WHERE id = ?
        """, (
            datetime.now().isoformat(),
            stats.get("total_devices", stats.get("total", 0)),
            stats.get("high_risk", stats.get("high", 0)),
            stats.get("medium_risk", stats.get("medium", 0)),
            stats.get("low_risk", stats.get("low", 0)),
            stats.get("global_score", 0),
            scan_id
        ))


def get_scans(limit: int = 20) -> list:
    """Retourne les derniers scans."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_scan(scan_id: int) -> Optional[dict]:
    """Retourne un scan par ID."""
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None


def get_latest_scan() -> Optional[dict]:
    """Retourne le dernier scan complété."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE status = 'completed' ORDER BY finished_at DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None


# ── Devices ────────────────────────────────────────────────

def save_device(scan_id: int, device: dict) -> int:
    """Sauvegarde un appareil et retourne son ID."""
    with get_connection() as conn:
        cur = conn.execute("""
            INSERT INTO devices (scan_id, ip, mac, hostname, vendor, open_ports, risk_level, risk_score, detected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            device.get("ip", ""),
            device.get("mac", "Inconnu"),
            device.get("hostname", "Inconnu"),
            device.get("vendor", "Inconnu"),
            json.dumps(device.get("open_ports", [])),
            device.get("risk_level", "low"),
            device.get("risk_score", 0),
            datetime.now().isoformat()
        ))
        return cur.lastrowid


def get_devices(scan_id: int) -> list:
    """Retourne tous les appareils d'un scan."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM devices WHERE scan_id = ? ORDER BY risk_score DESC",
            (scan_id,)
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["open_ports"] = json.loads(d["open_ports"])
            result.append(d)
        return result


# ── Analyses ───────────────────────────────────────────────

def save_analysis(device_id: int, scan_id: int, analysis: dict) -> None:
    """Sauvegarde une analyse IA."""
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO analyses (device_id, scan_id, risk_level, risk_score, explanation, recommendations, analyzed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            device_id,
            scan_id,
            analysis.get("risk_level", "low"),
            analysis.get("risk_score", 0),
            analysis.get("explanation", ""),
            json.dumps(analysis.get("recommendations", [])),
            datetime.now().isoformat()
        ))


def get_analysis(device_id: int) -> Optional[dict]:
    """Retourne l'analyse d'un appareil."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM analyses WHERE device_id = ? ORDER BY analyzed_at DESC LIMIT 1",
            (device_id,)
        ).fetchone()
        if row:
            d = dict(row)
            d["recommendations"] = json.loads(d["recommendations"])
            return d
        return None


# ── Alerts ─────────────────────────────────────────────────

def save_alert(scan_id: int, device_ip: str, alert_type: str, message: str, severity: str = "medium") -> None:
    """Sauvegarde une alerte."""
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO alerts (scan_id, device_ip, alert_type, message, severity, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (scan_id, device_ip, alert_type, message, severity, datetime.now().isoformat()))


def get_alerts(scan_id: Optional[int] = None, limit: int = 50) -> list:
    """Retourne les alertes, optionnellement filtrées par scan."""
    with get_connection() as conn:
        if scan_id:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE scan_id = ? ORDER BY created_at DESC LIMIT ?",
                (scan_id, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]


def get_unacknowledged_alerts() -> list:
    """Retourne les alertes non acquittées."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE acknowledged = 0 ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


# ── Reports ────────────────────────────────────────────────

def save_report(scan_id: int, format: str, file_path: str) -> None:
    """Sauvegarde un rapport."""
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO reports (scan_id, format, file_path, created_at) VALUES (?, ?, ?, ?)",
            (scan_id, format, file_path, datetime.now().isoformat())
        )


def get_reports(limit: int = 20) -> list:
    """Retourne les rapports générés."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT r.*, s.network_range, s.total_devices FROM reports r JOIN scans s ON r.scan_id = s.id ORDER BY r.created_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


# ── Stats globales ─────────────────────────────────────────

def get_global_stats() -> dict:
    """Retourne les statistiques globales pour le dashboard."""
    with get_connection() as conn:
        total_scans = conn.execute("SELECT COUNT(*) FROM scans WHERE status='completed'").fetchone()[0]
        total_devices = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        total_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged=0").fetchone()[0]
        last_scan = get_latest_scan()
        return {
            "total_scans": total_scans,
            "total_devices": total_devices,
            "unacknowledged_alerts": total_alerts,
            "last_scan": last_scan,
        }