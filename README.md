# 🛡️ Network Surveillance Agent v2.0

Agent IA autonome de cybersécurité — surveillance réseau local avec dashboard Flask, analyse CrewAI et rapports PDF/JSON.

---

## 🎯 Fonctionnalités

| Fonctionnalité | Statut |
|---|---|
| Scan réseau local automatique | ✅ |
| Détection IP, MAC, hostname, fabricant | ✅ |
| Scan des ports sensibles (Nmap + socket) | ✅ |
| Analyse IA par appareil (OpenAI GPT-4o-mini) | ✅ |
| Agents CrewAI spécialisés (4 agents SOC) | ✅ |
| Stockage SQLite historique | ✅ |
| Dashboard Flask Bootstrap 5 dark | ✅ |
| Rapports PDF professionnels | ✅ |
| Rapports JSON structurés | ✅ |
| Surveillance continue (toutes les 5 min) | ✅ |
| Alertes de sécurité en temps réel | ✅ |

---

## 🏗️ Architecture

```
network-surveillance-agent/
│
├── app/
│   ├── __init__.py
│   ├── scanner.py      ← Scan réseau (Nmap + socket + Scapy)
│   ├── analyzer.py     ← Analyse des risques (local + OpenAI)
│   ├── ai_agent.py     ← Agents CrewAI spécialisés
│   ├── reporter.py     ← Génération rapports PDF + JSON
│   ├── database.py     ← Gestion SQLite
│   └── utils.py        ← Utilitaires communs
│
├── web/
│   ├── __init__.py
│   ├── app.py          ← Application Flask + routes API
│   └── templates/
│       ├── index.html  ← Dashboard principal
│       ├── devices.html ← Page des appareils
│       └── reports.html ← Page des rapports
│
├── reports/            ← Rapports générés (PDF + JSON)
├── database/           ← Base SQLite
├── .env.example        ← Template de configuration
├── requirements.txt    ← Dépendances Python
├── main.py             ← Point d'entrée
└── README.md
```

---

## 🚀 Installation

### 1. Cloner / extraire le projet

```powershell
cd network-surveillance-agent
```

### 2. Créer un environnement virtuel

```powershell
python -m venv mon_env
mon_env\Scripts\activate          # Windows
source mon_env/bin/activate       # Mac/Linux
```

### 3. Installer les dépendances

```powershell
pip install -r requirements.txt
```

### 4. Configurer

```powershell
copy .env.example .env
notepad .env
```

Remplis ta clé OpenAI :
```
OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxx
```

### 5. Lancer

```powershell
python main.py
```

Le navigateur s'ouvre automatiquement sur **http://localhost:5000** 🌐

---

## 🎮 Modes de lancement

```powershell
# Dashboard web (défaut)
python main.py

# Dashboard + surveillance continue (toutes les 5 min)
python main.py --continuous

# Scan unique sans interface web
python main.py --scan-only
```

---

## 🤖 Agents CrewAI

| Agent | Rôle | Spécialité |
|---|---|---|
| ScannerAgent | Analyste SOC Niveau 1 | Collecte et normalisation des données |
| RiskAgent | Expert Risques Cyber | Évaluation technique et priorisation |
| AlertAgent | Gestionnaire d'Alertes | Détection des menaces critiques |
| ReportAgent | Rédacteur SOC | Rapport final professionnel |

---

## 🔌 Ports surveillés

| Port | Service | Risque |
|---|---|---|
| 21 | FTP | 🔴 Élevé |
| 22 | SSH | 🟡 Moyen |
| 23 | Telnet | 🔴 Critique |
| 80 | HTTP | 🟢 Faible |
| 443 | HTTPS | 🟢 Faible |
| 3306 | MySQL | 🔴 Élevé |
| 3389 | RDP | 🔴 Élevé |
| 5432 | PostgreSQL | 🔴 Élevé |

---

## ⚠️ Avertissement légal

Cet outil est conçu **uniquement** pour surveiller ton propre réseau local.
Scanner un réseau sans autorisation explicite est **illégal**.

---

## 📄 Exemple de rapport JSON

```json
{
  "metadata": {
    "report_id": "NSA-1-20260511_180000",
    "generated_at": "2026-05-11T18:00:00",
    "tool": "Network Surveillance Agent v2.0"
  },
  "scan_summary": {
    "network_range": "192.168.1.0/24",
    "total_devices": 3,
    "high_risk": 0,
    "medium_risk": 0,
    "low_risk": 3,
    "global_score": 0
  },
  "devices": [
    {
      "ip": "192.168.1.1",
      "hostname": "SAX1V1S.lan",
      "mac": "AA:BB:CC:DD:EE:FF",
      "vendor": "Fabricant inconnu",
      "open_ports": [
        {"port": 80, "description": "HTTP — Serveur web non sécurisé"},
        {"port": 443, "description": "HTTPS — Serveur web sécurisé"}
      ],
      "risk_level": "low",
      "risk_score": 0,
      "explanation": "Le routeur expose les ports HTTP et HTTPS standards.",
      "recommendations": ["Activer HTTPS uniquement", "Désactiver l'accès HTTP"]
    }
  ]
}
```
