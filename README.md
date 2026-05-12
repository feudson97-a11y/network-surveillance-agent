# 🛡️ Network Surveillance Agent v2.0

An autonomous AI cybersecurity agent for local network monitoring with a Flask dashboard, CrewAI analysis, and PDF/JSON reports.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.1-green?logo=flask)
![CrewAI](https://img.shields.io/badge/CrewAI-0.80-purple)
![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4o--mini-orange?logo=openai)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 🎯 Features

| Feature | Status |
|---|---|
| Automatic local network scanning | ✅ |
| Device detection (IP, MAC, hostname, vendor) | ✅ |
| Port scanning with Nmap + socket | ✅ |
| AI-powered risk analysis (OpenAI GPT-4o-mini) | ✅ |
| 4 specialized CrewAI SOC agents | ✅ |
| SQLite history storage | ✅ |
| Flask Bootstrap 5 dark dashboard | ✅ |
| Professional PDF reports | ✅ |
| Structured JSON reports | ✅ |
| Continuous surveillance (every 5 min) | ✅ |
| Real-time security alerts | ✅ |

---

## 🏗️ Architecture

```
network-surveillance-agent/
│
├── app/
│   ├── scanner.py      ← Network scan (Nmap + socket + Scapy)
│   ├── analyzer.py     ← Risk analysis (local + OpenAI)
│   ├── ai_agent.py     ← Specialized CrewAI agents
│   ├── reporter.py     ← PDF + JSON report generation
│   ├── database.py     ← SQLite management
│   └── utils.py        ← Shared utilities
│
├── web/
│   ├── app.py          ← Flask application + API routes
│   └── templates/
│       ├── index.html  ← Main dashboard
│       ├── devices.html ← Devices page
│       └── reports.html ← Reports page
│
├── reports/            ← Generated reports (PDF + JSON)
├── database/           ← SQLite database
├── .env.example        ← Configuration template
├── requirements.txt    ← Python dependencies
├── main.py             ← Entry point
└── README.md
```

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/feudson97-a11y/network-surveillance-agent.git
cd network-surveillance-agent
```

### 2. Create a virtual environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Mac/Linux
python -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment

```bash
# Windows
copy .env.example .env

# Mac/Linux
cp .env.example .env
```

Edit `.env` and add your OpenAI API key:
```
OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxx
```

### 5. Run the application

```bash
python main.py
```

The browser opens automatically at **http://localhost:5000**

---

## 🎮 Launch Modes

```bash
# Web dashboard (default)
python main.py

# Dashboard + continuous surveillance (every 5 min)
python main.py --continuous

# Single scan without web interface
python main.py --scan-only
```

---

## 🤖 CrewAI Agents

| Agent | Role | Specialty |
|---|---|---|
| ScannerAgent | SOC Analyst Level 1 | Data collection and normalization |
| RiskAgent | Cyber Risk Expert | Technical evaluation and prioritization |
| AlertAgent | Alert Manager | Critical threat detection |
| ReportAgent | SOC Writer | Final professional report |

---

## 🔌 Monitored Ports

| Port | Service | Risk |
|---|---|---|
| 21 | FTP | 🔴 High |
| 22 | SSH | 🟡 Medium |
| 23 | Telnet | 🔴 Critical |
| 80 | HTTP | 🟢 Low |
| 443 | HTTPS | 🟢 Low |
| 3306 | MySQL | 🔴 High |
| 3389 | RDP | 🔴 High |
| 5432 | PostgreSQL | 🔴 High |

---

## ⚠️ Legal Notice

This tool is designed **only** to monitor your own local network.
Scanning a network without explicit authorization is **illegal**.

---

## 📝 License

MIT License

---

## 👤 Author

**feudson97-a11y**
- GitHub: [@feudson97-a11y](https://github.com/feudson97-a11y)
