"""
CLI principal del Automatizador de Threat Intelligence & Triaje de IOCs (Mini-SOAR).

Uso:
    python main.py
    python main.py --input samples/raw_ticket_input.txt
"""

import argparse
from pathlib import Path
import sys

from src.enricher import enrich_all_iocs
from src.extractor import extract_iocs_from_text
from src.soar_reporter import generate_soar_json_report, generate_soar_markdown_report


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SOC L1 Threat Intelligence & IOC Triage Automator (Mini-SOAR)"
    )
    parser.add_argument(
        "--input",
        type=str,
        default="samples/raw_ticket_input.txt",
        help="Archivo de texto crudo del ticket SIEM con IOCs",
    )
    parser.add_argument(
        "--md-out",
        type=str,
        default="reports/SOAR_Threat_Intel_Report.md",
        help="Ruta de salida para el reporte Markdown",
    )
    parser.add_argument(
        "--json-out",
        type=str,
        default="reports/soar_enrichment.json",
        help="Ruta de salida para el reporte JSON",
    )
    return parser


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    args = build_arg_parser().parse_args()
    input_path = Path(args.input)

    print("=" * 88)
    print("  SOC L1 THREAT INTELLIGENCE & IOC TRIAGE AUTOMATOR (MINI-SOAR)")
    print("=" * 88)

    raw_text = input_path.read_text(encoding="utf-8")
    extracted = extract_iocs_from_text(raw_text)

    print(f"[+] Activos Internos RFC 1918 descartados de OSINT: {extracted.internal_private_ips}")
    print(
        f"[+] IOCs Externos extraídos: {len(extracted.public_ips)} IPs | "
        f"{len(extracted.urls_and_domains)} Dominios/URLs | "
        f"{len(extracted.sha256_hashes)} Hashes SHA-256"
    )
    print("-" * 88)

    enriched = enrich_all_iocs(extracted)

    print(f"{'VERDICT':<11} | {'SCORE':<7} | {'TYPE':<10} | {'IOC (DEFANGED)':<35} | {'INTEL / FAMILY'}")
    print("-" * 105)

    for r in enriched:
        short_ioc = (
            f"{r.defanged_value[:32]}..."
            if len(r.defanged_value) > 35
            else r.defanged_value
        )
        print(
            f"{r.verdict:<11} | {f'{r.risk_score}/100':<7} | {r.ioc_type:<10} | "
            f"{short_ioc:<35} | {r.isp_or_malware_family}"
        )

    print("-" * 105)
    md_path = generate_soar_markdown_report(extracted, enriched, args.md_out)
    json_path = generate_soar_json_report(extracted, enriched, args.json_out)

    print(f"\n[OK] Reporte CTI (Markdown) generado en: {md_path}")
    print(f"[OK] Exportación SOAR (JSON) generada en: {json_path}")
    print("=" * 88)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
