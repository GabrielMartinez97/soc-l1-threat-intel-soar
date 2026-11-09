"""
Generador de Reportes de Enriquecimiento Threat Intelligence y Playbook SOAR (SOC L1).
"""

from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Dict, List

from src.enricher import EnrichedIOC
from src.extractor import ExtractedIOCs

VERDICT_BADGE: Dict[str, str] = {
    "MALICIOUS": "🔴 MALICIOUS",
    "SUSPICIOUS": "🟠 SUSPICIOUS",
    "BENIGN": "🟢 BENIGN (Falso Positivo)",
}


def generate_soar_markdown_report(
    extracted: ExtractedIOCs,
    enriched_list: List[EnrichedIOC],
    output_path: str | Path,
) -> Path:
    """Genera el reporte de enriquecimiento CTI en Markdown listo para adjuntar al ticket SIEM."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    counts = {"MALICIOUS": 0, "SUSPICIOUS": 0, "BENIGN": 0}
    for item in enriched_list:
        counts[item.verdict] = counts.get(item.verdict, 0) + 1

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: List[str] = [
        "# 🕵️‍♂️ Reporte de Enriquecimiento Threat Intelligence (SOAR — SOC L1)",
        "",
        f"**Fecha de Análisis:** `{now_str}`  ",
        "**Analista SOC L1:** Gabriel Martínez (`@GabrielMartinez97`)  ",
        f"**Total IOCs Externos Analizados:** `{len(enriched_list)}`  ",
        f"**Activos Internos (RFC 1918) Filtrados:** `{', '.join(extracted.internal_private_ips)}`",
        "",
        "---",
        "",
        "## 📊 1. Resumen de Veredictos CTI",
        "",
        "| Veredicto SOAR | Cantidad | Acción Operativa |",
        "| :--- | :---: | :--- |",
        f"| 🔴 **MALICIOUS** | **{counts['MALICIOUS']}** | Bloqueo inmediato en Firewall/EDR y Escalado a SOC L2 |",
        f"| 🟠 **SUSPICIOUS** | **{counts['SUSPICIOUS']}** | Bloqueo preventivo en WAF y monitoreo en Watchlist |",
        f"| 🟢 **BENIGN** | **{counts['BENIGN']}** | **NO BLOQUEAR** — Infraestructura legítima / Falso Positivo |",
        "",
        "---",
        "",
        "## 🌐 2. Tabla Resumen de Indicadores Enriquecidos (Defanged)",
        "",
        "| IOC (Defanged) | Tipo | Veredicto | Risk Score | VirusTotal | AbuseIPDB | Origen / Familia |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :--- |",
    ]

    for item in enriched_list:
        badge = VERDICT_BADGE.get(item.verdict, item.verdict)
        short_ioc = (
            f"{item.defanged_value[:24]}..."
            if len(item.defanged_value) > 28 and item.ioc_type == "SHA-256"
            else item.defanged_value
        )
        lines.append(
            f"| `{short_ioc}` | `{item.ioc_type}` | {badge} | **{item.risk_score}/100** | "
            f"`{item.vt_detections}` | `{item.abuse_score}%` | {item.isp_or_malware_family} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 🔍 3. Ficha Técnica Detallada y Playbook por Indicador",
        "",
    ])

    for idx, item in enumerate(enriched_list, start=1):
        badge = VERDICT_BADGE.get(item.verdict, item.verdict)
        lines.extend([
            f"### {idx}. [{badge}] `{item.defanged_value}` ({item.ioc_type})",
            "",
            f"- **Puntaje de Riesgo SOAR:** `{item.risk_score}/100` (AbuseIPDB: `{item.abuse_score}%` | VirusTotal: `{item.vt_detections}`)",
            f"- **Origen / Ubicación:** {item.country_or_origin}",
            f"- **ISP / Familia de Malware:** `{item.isp_or_malware_family}`",
            f"- **Fuente de Inteligencia:** {item.source_feed}",
            f"- **Contexto del Analista:** {item.analyst_summary}",
            f"- **Acción SOAR Recomendada:** **{item.soar_action}**",
            "",
        ])

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def generate_soar_json_report(
    extracted: ExtractedIOCs,
    enriched_list: List[EnrichedIOC],
    output_path: str | Path,
) -> Path:
    """Exporta el enriquecimiento de IOCs en formato JSON para automatización SOAR."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "analyst": "GabrielMartinez97",
        "internal_rfc1918_assets": extracted.internal_private_ips,
        "enriched_iocs": [asdict(item) for item in enriched_list],
    }

    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
