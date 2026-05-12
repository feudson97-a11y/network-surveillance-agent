"""
app/ai_agent.py — Agents CrewAI spécialisés
=============================================
4 agents SOC spécialisés :
- ScannerAgent    → collecte données réseau
- RiskAgent       → analyse technique des risques
- ReportAgent     → génère le rapport final
- AlertAgent      → déclenche les alertes critiques
"""

import os
import json
from dotenv import load_dotenv

load_dotenv()


def run_crewai_analysis(devices: list, scan_summary: dict) -> dict:
    """
    Lance le pipeline CrewAI complet sur les données du scan.
    Retourne un rapport structuré avec analyse et recommandations.
    """
    openai_key = os.getenv("OPENAI_API_KEY", "")
    if not openai_key or openai_key.startswith("sk-proj-xxx"):
        return _fallback_analysis(devices, scan_summary)

    try:
        from crewai import Agent, Task, Crew, Process

        # ── Données préparées pour les agents ──────────────────
        devices_summary = json.dumps(scan_summary, ensure_ascii=False, indent=2)

        high_risk = [d for d in devices if d.get("risk_level") == "high"]
        medium_risk = [d for d in devices if d.get("risk_level") == "medium"]

        # ── Définition des agents ──────────────────────────────

        scanner_agent = Agent(
            role="Analyste Réseau SOC Niveau 1",
            goal="Collecter et synthétiser les données brutes du scan réseau",
            backstory=(
                "Tu es un analyste SOC niveau 1 spécialisé dans la collecte "
                "et la normalisation des données réseau. Tu transformes les données "
                "brutes de scan en informations structurées et compréhensibles."
            ),
            verbose=False,
            allow_delegation=False,
        )

        risk_agent = Agent(
            role="Expert en Analyse de Risques Cybersécurité",
            goal="Évaluer les risques techniques de chaque appareil et prioriser les menaces",
            backstory=(
                "Tu es un expert en cybersécurité avec 10 ans d'expérience en analyse "
                "de risques réseau. Tu identifies les vulnérabilités critiques, "
                "évalues leur impact et priorises les actions de remédiation."
            ),
            verbose=False,
            allow_delegation=False,
        )

        report_agent = Agent(
            role="Rédacteur de Rapports de Sécurité",
            goal="Produire un rapport de sécurité clair, structuré et exploitable",
            backstory=(
                "Tu es un expert en communication de sécurité. Tu transformes "
                "les analyses techniques en rapports clairs, actionnables et "
                "compréhensibles pour des non-experts en cybersécurité."
            ),
            verbose=False,
            allow_delegation=False,
        )

        alert_agent = Agent(
            role="Gestionnaire d'Alertes de Sécurité",
            goal="Identifier les menaces critiques nécessitant une action immédiate",
            backstory=(
                "Tu es responsable de la détection et de l'escalade des incidents "
                "de sécurité critiques. Tu analyses les alertes, évalues leur urgence "
                "et génères des notifications précises pour une réponse rapide."
            ),
            verbose=False,
            allow_delegation=False,
        )

        # ── Définition des tâches ──────────────────────────────

        scan_task = Task(
            description=(
                f"Analyse et synthétise ces données de scan réseau :\n{devices_summary}\n\n"
                "Produis un résumé structuré incluant :\n"
                "1. Nombre total d'appareils\n"
                "2. Répartition par niveau de risque\n"
                "3. Ports les plus préoccupants\n"
                "4. Appareils nécessitant attention prioritaire"
            ),
            expected_output="Résumé structuré du scan réseau en français, 200-300 mots.",
            agent=scanner_agent,
        )

        risk_task = Task(
            description=(
                f"Sur la base du scan réseau, analyse en détail les risques :\n"
                f"Appareils à risque élevé : {len(high_risk)}\n"
                f"Appareils à risque moyen : {len(medium_risk)}\n\n"
                "Pour chaque appareil à risque (élevé ou moyen), fournis :\n"
                "1. Description technique de la vulnérabilité\n"
                "2. Impact potentiel\n"
                "3. Vecteur d'attaque possible\n"
                "4. Priorité de remédiation (P1/P2/P3)"
            ),
            expected_output="Analyse technique des risques par appareil, avec priorités claires.",
            agent=risk_agent,
            context=[scan_task],
        )

        alert_task = Task(
            description=(
                "Identifie toutes les alertes critiques nécessitant une action immédiate.\n"
                "Pour chaque alerte :\n"
                "1. Décris la menace spécifique\n"
                "2. Indique le niveau de sévérité (CRITIQUE/HAUTE/MOYENNE)\n"
                "3. Propose une action immédiate (dans les 24h)\n"
                "Concentre-toi uniquement sur les problèmes urgents."
            ),
            expected_output="Liste des alertes critiques avec actions immédiates requises.",
            agent=alert_agent,
            context=[risk_task],
        )

        report_task = Task(
            description=(
                "Rédige un rapport de sécurité réseau complet et professionnel en français.\n"
                "Structure obligatoire :\n"
                "## Résumé Exécutif\n"
                "## État du Réseau\n"
                "## Appareils à Risque\n"
                "## Alertes Critiques\n"
                "## Plan de Remédiation\n"
                "## Conclusion\n\n"
                "Le rapport doit être compréhensible par un non-expert "
                "tout en restant techniquement précis."
            ),
            expected_output="Rapport de sécurité complet, structuré et professionnel en français.",
            agent=report_agent,
            context=[scan_task, risk_task, alert_task],
        )

        # ── Lancement du crew ──────────────────────────────────
        crew = Crew(
            agents=[scanner_agent, risk_agent, alert_agent, report_agent],
            tasks=[scan_task, risk_task, alert_task, report_task],
            process=Process.sequential,
            verbose=False,
        )

        result = crew.kickoff()

        return {
            "crew_report": str(result),
            "ai_powered": True,
            "agents_used": ["ScannerAgent", "RiskAgent", "AlertAgent", "ReportAgent"],
        }

    except Exception as e:
        print(f"⚠️  CrewAI non disponible : {e}")
        return _fallback_analysis(devices, scan_summary)


def _fallback_analysis(devices: list, scan_summary: dict) -> dict:
    """Analyse locale si CrewAI/OpenAI non disponible."""
    high = [d for d in devices if d.get("risk_level") == "high"]
    medium = [d for d in devices if d.get("risk_level") == "medium"]

    report = f"""## Résumé Exécutif
{len(devices)} appareil(s) détecté(s) sur le réseau local.
{len(high)} appareil(s) à risque élevé, {len(medium)} à risque moyen.

## État du Réseau
Total appareils : {scan_summary.get('total_devices', len(devices))}
Risque élevé : {len(high)}
Risque moyen : {len(medium)}
Risque faible : {len(devices) - len(high) - len(medium)}

## Plan de Remédiation
1. Fermez les ports inutilisés sur tous les appareils
2. Désactivez Telnet et remplacez par SSH
3. Protégez les bases de données derrière un pare-feu
4. Activez les mises à jour automatiques
5. Changez les mots de passe par défaut

## Conclusion
Activez OpenAI pour une analyse personnalisée et détaillée."""

    return {
        "crew_report": report,
        "ai_powered": False,
        "agents_used": [],
    }
