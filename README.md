# 🕵️‍♂️ SOC L1 Threat Intelligence & IOC Triage Automator (Mini-SOAR)

![Role](https://img.shields.io/badge/Role-SOC%20Analyst%20L1-0A66C2?style=flat-square)
![Capability](https://img.shields.io/badge/Capability-SOAR%20%26%20OSINT%20Enrichment-2EA44F?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square)

Herramienta de automatización de respuesta y enriquecimiento de **Indicadores de Compromiso (IOCs)** diseñada para acelerar el triaje de un **Analista SOC Nivel 1 (Tier 1)** reduciendo el **MTTR** (*Mean Time To Respond*).

---

## 🎯 ¿Qué problema resuelve en un SOC Nivel 1?

Cuando el SIEM genera una alerta (como las de nuestro [Proyecto 1: Mini-SIEM](https://github.com/GabrielMartinez97/soc-l1-log-analyzer-siem)), el analista SOC L1 recibe un ticket lleno de direcciones IP, dominios, URLs y hashes de archivos (`SHA-256`).

Investigar manualmente cada indicador abriendo pestañas en **VirusTotal**, **AbuseIPDB** y **URLhaus** toma entre 15 y 20 minutos por ticket. Este **Mini-SOAR** automatiza todo el flujo en segundos:

1. **Extracción y Refanging:** Extrae automáticamente IPs, dominios, URLs y hashes `SHA-256` desde texto crudo (incluso si están *defanged* como `185.220.101[.]45`).
2. **Filtrado de IPs Privadas (RFC 1918):** Descarta automáticamente IPs internas de la empresa (`10.x.x.x`, `192.168.x.x`, `172.16-31.x.x`) para no enviarlas a APIs públicas ni perder tiempo investigando IPs locales en OSINT.
3. **Enriquecimiento Threat Intelligence (OSINT):** Consulta **AbuseIPDB** y **VirusTotal** (con soporte para API Keys reales en `.env` o base de inteligencia CTI local para pruebas offline).
4. **Cálculo de Riesgo y Veredicto SOAR:** Clasifica cada IOC como `MALICIOUS`, `SUSPICIOUS` o `BENIGN` y genera la nota de triaje con los IOCs nuevamente *defanged* lista para pegar en el ticket.

---

## 🏗️ Arquitectura del Flujo SOAR

```mermaid
flowchart LR
    A["Ticket / Alerta Cruda\n(IPs, URLs, Hashes SHA-256)"] --> B["Extractor & Refanger\n(Filtra IPs Privadas RFC1918)"]
    B --> C["Motor de Enriquecimiento CTI\n(VirusTotal + AbuseIPDB / Offline Feed)"]
    C --> D["Calculadora de Riesgo\n(Score 0-100 & Veredicto SOC)"]
    D --> E["Reporte de Enriquecimiento L1\n(Markdown + JSON Defanged)"]
```

---

## 📂 Estructura del Proyecto

```text
soc-l1-threat-intel-soar/
├── samples/
│   └── raw_ticket_input.txt    # Ticket SIEM simulado con IPs internas/externas, URLs y hashes
├── src/
│   ├── __init__.py
│   ├── extractor.py            # Extracción regex, Refanging, Defanging y filtro RFC 1918
│   ├── enricher.py             # Clientes API (VirusTotal/AbuseIPDB) + Feed CTI de respaldo
│   └── soar_reporter.py        # Generador de veredicto y plantilla de triaje SOC L1
├── reports/                    # Reportes de Threat Intelligence generados
├── tests/                      # Pruebas unitarias
├── .env.example                # Plantilla segura para API Keys
├── main.py                     # CLI principal del Mini-SOAR
└── README.md
```

---

## 👤 Autor

* **Gabriel Martínez** ([@GabrielMartinez97](https://github.com/GabrielMartinez97)) — *Cybersecurity SOC L1 Portfolio*
