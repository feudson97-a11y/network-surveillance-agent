"""
app/scanner.py — Scanner réseau
==================================
Scanne le réseau local, détecte les appareils,
récupère MAC, hostname, vendor et ports ouverts via Nmap.
"""

import socket
import json
import os
from typing import Optional
from app.utils import ping_host, get_hostname, get_local_ip, get_network_range

# Ports sensibles à surveiller obligatoirement
SENSITIVE_PORTS = [21, 22, 23, 80, 443, 3389, 8080, 3306, 5432, 25, 8443]

# Description des ports
PORT_DESCRIPTIONS = {
    21:   "FTP — Transfert de fichiers non sécurisé",
    22:   "SSH — Accès shell distant",
    23:   "Telnet — Protocole non sécurisé (obsolète)",
    25:   "SMTP — Serveur email",
    80:   "HTTP — Serveur web non sécurisé",
    443:  "HTTPS — Serveur web sécurisé",
    3306: "MySQL — Base de données exposée",
    3389: "RDP — Bureau à distance Windows",
    5432: "PostgreSQL — Base de données exposée",
    8080: "HTTP alternatif",
    8443: "HTTPS alternatif",
}


def get_mac_address(ip: str) -> str:
    """
    Tente de récupérer l'adresse MAC via ARP.
    Fonctionne uniquement si Scapy est disponible et les droits admin.
    """
    try:
        from scapy.all import ARP, Ether, srp
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=1, verbose=False)[0]
        if result:
            return result[0][1].hwsrc
        return "Inconnu"
    except Exception:
        return "Inconnu"


def get_vendor_from_mac(mac: str) -> str:
    """
    Identifie le fabricant depuis les 3 premiers octets du MAC.
    Utilise une mini-table locale pour les fabricants courants.
    """
    if mac == "Inconnu" or len(mac) < 8:
        return "Inconnu"

    prefix = mac.upper().replace("-", ":")[0:8]
    vendors = {
        "00:50:56": "VMware",
        "08:00:27": "VirtualBox",
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "00:1A:2B": "Cisco",
        "00:0C:29": "VMware",
        "AC:BC:32": "Apple",
        "F0:18:98": "Apple",
        "3C:22:FB": "Apple",
        "18:65:90": "Apple",
        "00:16:3E": "Xen",
        "52:54:00": "QEMU",
    }
    return vendors.get(prefix, "Fabricant inconnu")


def scan_ports(ip: str) -> list:
    """
    Scanne les ports sensibles sur un appareil via socket.
    Plus rapide que Nmap pour les ports connus.
    Retourne la liste des ports ouverts avec leur description.
    """
    open_ports = []
    for port in SENSITIVE_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                result = sock.connect_ex((str(ip), port))
                if result == 0:
                    open_ports.append({
                        "port": port,
                        "description": PORT_DESCRIPTIONS.get(port, f"Port {port}"),
                        "state": "open"
                    })
        except Exception:
            pass
    return open_ports


def scan_ports_nmap(ip: str) -> list:
    """
    Scanne les ports via python-nmap (plus précis).
    Fallback vers scan_ports() si nmap non disponible.
    """
    try:
        import nmap
        nm = nmap.PortScanner()
        ports_str = ",".join(str(p) for p in SENSITIVE_PORTS)
        nm.scan(str(ip), ports_str, arguments="-sV --open -T4")

        open_ports = []
        if str(ip) in nm.all_hosts():
            host = nm[str(ip)]
            for proto in host.all_protocols():
                for port in host[proto].keys():
                    state = host[proto][port]["state"]
                    if state == "open":
                        service = host[proto][port].get("name", "unknown")
                        open_ports.append({
                            "port": port,
                            "description": PORT_DESCRIPTIONS.get(port, f"{service} (port {port})"),
                            "state": "open",
                            "service": service,
                        })
        return open_ports
    except Exception:
        return scan_ports(ip)


def scan_device(ip: str, use_nmap: bool = True) -> dict:
    """
    Scanne un appareil complet :
    - hostname
    - adresse MAC
    - fabricant
    - ports ouverts
    """
    hostname = get_hostname(str(ip))
    mac = get_mac_address(str(ip))
    vendor = get_vendor_from_mac(mac)

    if use_nmap:
        open_ports = scan_ports_nmap(str(ip))
    else:
        open_ports = scan_ports(str(ip))

    return {
        "ip": str(ip),
        "hostname": hostname,
        "mac": mac,
        "vendor": vendor,
        "open_ports": open_ports,
        "status": "online",
    }


def scan_network(network_range: Optional[str] = None, max_hosts: int = 254) -> list:
    """
    Scanne tout le réseau et retourne la liste des appareils trouvés.

    Args:
        network_range: Plage IP ex: '192.168.1.0/24' (auto-détectée si None)
        max_hosts: Nombre maximum d'hôtes à scanner

    Returns:
        Liste de dicts représentant chaque appareil trouvé
    """
    import ipaddress

    if not network_range:
        local_ip = get_local_ip()
        network_range = get_network_range(local_ip)

    print(f"\n🔍 Scan du réseau : {network_range}")
    print("⏳ Recherche des appareils...\n")

    network = ipaddress.IPv4Network(network_range, strict=False)
    devices = []
    hosts = list(network.hosts())[:max_hosts]

    for ip in hosts:
        if ping_host(str(ip)):
            print(f"  ✅ Appareil trouvé : {ip}")
            device = scan_device(str(ip))
            devices.append(device)
            if device["open_ports"]:
                port_nums = [p["port"] for p in device["open_ports"]]
                print(f"     Ports ouverts : {port_nums}")

    print(f"\n📊 {len(devices)} appareil(s) détecté(s) sur {network_range}")
    return devices
