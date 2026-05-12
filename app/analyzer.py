"""
app/analyzer.py — Analyse des risques
=======================================
Évalue le niveau de risque de chaque appareil.
Deux modes : local (règles) et IA (OpenAI GPT-4o-mini).
"""

import os
import json
from dotenv import load_dotenv

load_dotenv()

# Ports et leurs niveaux de risque
PORT_RISK = {
    23:   {"score": 4, "label": "Telnet non sécurisé — critique"},
    21:   {"score": 3, "label": "FTP non chiffré"},
    3306: {"score": 3, "label": "MySQL exposé sur le réseau"},
    5432: {"score": 3, "label": "PostgreSQL exposé sur le réseau"},
    25:   {"score": 2, "label": "SMTP — serveur email suspect"},
    3389: {"score": 2, "label": "RDP — bureau à distance exposé"},
    22:   {"score": 1, "label": "SSH — accès distant (surveiller)"},
    8080: {"score": 1, "label": "HTTP alternatif"},
    80:   {"score": 0, "label": "HTTP standard"},
    443:  {"score": 0, "label": "HTTPS sécurisé"},
}


def calculate_risk(device: dict) -> dict:
    """
    Calcule le niveau de risque local d'un appareil.
    Retourne : risk_level, risk_score, risk_reasons
    """
    open_ports = device.get("open_ports", [])
    risk_score = 0
    risk_reasons = []

    for port_info in open_ports:
        port = port_info.get("port") if isinstance(port_info, dict) else port_info
        if port in PORT_RISK:
            score = PORT_RISK[port]["score"]
            label = PORT_RISK[port]["label"]
            risk_score += score
            if score > 0:
                risk_reasons.append(f"Port {port} : {label}")

    # Déterminer le niveau
    if risk_score >= 4:
        risk_level = "high"
    elif risk_score >= 2:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "risk_level": risk_level,
        "risk_score": min(risk_score, 10),
        "risk_reasons": risk_reasons,
    }


def analyze_device_with_ai(device: dict) -> dict:
    """
    Analyse un appareil avec OpenAI GPT-4o-mini.
    Retourne une analyse SOC complète.
    """
    openai_key = os.getenv("OPENAI_API_KEY", "")
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    # Calcul du risque local d'abord
    local_risk = calculate_risk(device)

    if not openai_key or openai_key.startswith("sk-proj-xxx"):
        return {
            **local_risk,
            "explanation": "Analyse locale (OpenAI non configuré).",
            "recommendations": [
                "Fermez les ports inutilisés",
                "Activez un pare-feu",
                "Mettez à jour vos appareils",
            ],
            "ai_powered": False,
        }

    try:
        from openai import OpenAI
        client = OpenAI(api_key=openai_key)

        port_list = [
            f"Port {p.get('port', p)} ({p.get('description', '')})"
            if isinstance(p, dict) else f"Port {p}"
            for p in device.get("open_ports", [])
        ]

        prompt = f"""Tu es un analyste SOC expert en cybersécurité réseau.
Analyse cet appareil détecté sur un réseau local et fournis une analyse technique en JSON.

APPAREIL :
- IP : {device.get('ip')}
- Hostname : {device.get('hostname')}
- MAC : {device.get('mac')}
- Fabricant : {device.get('vendor')}
- Ports ouverts : {', '.join(port_list) if port_list else 'Aucun'}
- Risque calculé localement : {local_risk['risk_level']} (score: {local_risk['risk_score']}/10)

Réponds UNIQUEMENT en JSON valide avec cette structure exacte :
{{
  "risk_level": "low|medium|high",
  "risk_score": <entier 0-10>,
  "explanation": "<explication technique en français, 2-3 phrases>",
  "recommendations": [
    "<recommandation 1 concrète>",
    "<recommandation 2 concrète>",
    "<recommandation 3 concrète>"
  ]
}}"""

        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "Tu es un expert SOC. Réponds uniquement en JSON valide, sans markdown."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=400,
            temperature=0.2,
        )

        content = response.choices[0].message.content.strip()
        # Nettoyer si markdown présent
        content = content.replace("```json", "").replace("```", "").strip()
        analysis = json.loads(content)
        analysis["ai_powered"] = True
        return analysis

    except json.JSONDecodeError:
        return {**local_risk, "explanation": "Erreur de parsing IA.", "recommendations": [], "ai_powered": False}
    except Exception as e:
        return {**local_risk, "explanation": f"IA indisponible : {e}", "recommendations": [], "ai_powered": False}


def analyze_all_devices(devices: list) -> list:
    """
    Analyse tous les appareils et retourne la liste enrichie.
    """
    print("\n🤖 Analyse IA des appareils...")
    analyzed = []
    for device in devices:
        print(f"  Analyse de {device['ip']}...")
        analysis = analyze_device_with_ai(device)
        analyzed.append({**device, **analysis})
    print(f"✅ {len(analyzed)} appareil(s) analysé(s)")
    return analyzed
