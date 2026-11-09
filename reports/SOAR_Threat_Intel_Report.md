# 🕵️‍♂️ Reporte de Enriquecimiento Threat Intelligence (SOAR — SOC L1)

**Fecha de Análisis:** `2026-11-09 01:50:58 UTC`  
**Analista SOC L1:** Gabriel Martínez (`@GabrielMartinez97`)  
**Total IOCs Externos Analizados:** `9`  
**Activos Internos (RFC 1918) Filtrados:** `10.10.20.15, 192.168.1.50`

---

## 📊 1. Resumen de Veredictos CTI

| Veredicto SOAR | Cantidad | Acción Operativa |
| :--- | :---: | :--- |
| 🔴 **MALICIOUS** | **6** | Bloqueo inmediato en Firewall/EDR y Escalado a SOC L2 |
| 🟠 **SUSPICIOUS** | **1** | Bloqueo preventivo en WAF y monitoreo en Watchlist |
| 🟢 **BENIGN** | **2** | **NO BLOQUEAR** — Infraestructura legítima / Falso Positivo |

---

## 🌐 2. Tabla Resumen de Indicadores Enriquecidos (Defanged)

| IOC (Defanged) | Tipo | Veredicto | Risk Score | VirusTotal | AbuseIPDB | Origen / Familia |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| `24d004a104d4d54034dbcffc...` | `SHA-256` | 🔴 MALICIOUS | **100/100** | `68/72 motores` | `100%` | Familia: Ransomware.WannaCry / Cryptor |
| `198.51.100[.]77` | `IPv4` | 🔴 MALICIOUS | **96/100** | `22/90 motores` | `98%` | Offshore VPS Hosting |
| `185.220.101[.]45` | `IPv4` | 🔴 MALICIOUS | **95/100** | `18/90 motores` | `100%` | Zwiebelfreunde e.V. (Tor Network) |
| `hxxp://c2.attacker-domain[.]xyz/collect` | `URL/Domain` | 🔴 MALICIOUS | **92/100** | `31/90 motores` | `95%` | C2 Credential Harvester |
| `drop.darknet-loader[.]ru` | `URL/Domain` | 🔴 MALICIOUS | **88/100** | `27/90 motores` | `90%` | Malware Dropper Infrastructure |
| `45.155.205[.]109` | `IPv4` | 🔴 MALICIOUS | **85/100** | `14/90 motores` | `92%` | Selectel Bulletproof Hosting |
| `91.240.118[.]222` | `IPv4` | 🟠 SUSPICIOUS | **58/100** | `6/90 motores` | `65%` | Scanner Cloud ASN |
| `8.8.8[.]8` | `IPv4` | 🟢 BENIGN (Falso Positivo) | **0/100** | `0/90 motores` | `0%` | Google LLC (Google Public DNS) |
| `e3b0c44298fc1c149afbf4c8...` | `SHA-256` | 🟢 BENIGN (Falso Positivo) | **0/100** | `0/72 motores` | `0%` | Microsoft Windows Genuine File (Empty/Clean Hash) |

---

## 🔍 3. Ficha Técnica Detallada y Playbook por Indicador

### 1. [🔴 MALICIOUS] `24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c` (SHA-256)

- **Puntaje de Riesgo SOAR:** `100/100` (AbuseIPDB: `100%` | VirusTotal: `68/72 motores`)
- **Origen / Ubicación:** Archivo Binario (/tmp/kworker_crypt.elf)
- **ISP / Familia de Malware:** `Familia: Ransomware.WannaCry / Cryptor`
- **Fuente de Inteligencia:** Offline CTI Threat Feed (VirusTotal + AbuseIPDB Sim)
- **Contexto del Analista:** ¡CRÍTICO! Hash SHA-256 confirmado como Ransomware (WannaCry). El atacante camufló el binario bajo el nombre 'kworker_crypt.elf'.
- **Acción SOAR Recomendada:** **AISLAR HOST INMEDIATAMENTE en EDR, matar proceso asociado al hash, agregar SHA-256 a lista de bloqueo global y escalar a SOC Nivel 2.**

### 2. [🔴 MALICIOUS] `198.51.100[.]77` (IPv4)

- **Puntaje de Riesgo SOAR:** `96/100` (AbuseIPDB: `98%` | VirusTotal: `22/90 motores`)
- **Origen / Ubicación:** NL (Netherlands)
- **ISP / Familia de Malware:** `Offshore VPS Hosting`
- **Fuente de Inteligencia:** Offline CTI Threat Feed (VirusTotal + AbuseIPDB Sim)
- **Contexto del Analista:** Actor de amenaza activo ejecutando explotación web (SQL Injection con sqlmap y robo de /etc/passwd).
- **Acción SOAR Recomendada:** **BLOQUEAR IOC en Firewall/WAF/Proxy DNS inmediatamente, buscar conexiones históricas en SIEM y escalar incidente a SOC Nivel 2.**

### 3. [🔴 MALICIOUS] `185.220.101[.]45` (IPv4)

- **Puntaje de Riesgo SOAR:** `95/100` (AbuseIPDB: `100%` | VirusTotal: `18/90 motores`)
- **Origen / Ubicación:** DE / Tor Exit Node
- **ISP / Familia de Malware:** `Zwiebelfreunde e.V. (Tor Network)`
- **Fuente de Inteligencia:** Offline CTI Threat Feed (VirusTotal + AbuseIPDB Sim)
- **Contexto del Analista:** Nodo de salida Tor reportado masivamente (1,420 reportes) por ataques de Fuerza Bruta SSH y comprometer cuentas.
- **Acción SOAR Recomendada:** **BLOQUEAR IOC en Firewall/WAF/Proxy DNS inmediatamente, buscar conexiones históricas en SIEM y escalar incidente a SOC Nivel 2.**

### 4. [🔴 MALICIOUS] `hxxp://c2.attacker-domain[.]xyz/collect` (URL/Domain)

- **Puntaje de Riesgo SOAR:** `92/100` (AbuseIPDB: `95%` | VirusTotal: `31/90 motores`)
- **Origen / Ubicación:** Domain Registrar: NameCheap (Privacy Guard)
- **ISP / Familia de Malware:** `C2 Credential Harvester`
- **Fuente de Inteligencia:** Offline CTI Threat Feed (VirusTotal + AbuseIPDB Sim)
- **Contexto del Analista:** Servidor de Comando y Control (C2) utilizado para recolectar cookies de sesión robadas vía Cross-Site Scripting (XSS).
- **Acción SOAR Recomendada:** **BLOQUEAR IOC en Firewall/WAF/Proxy DNS inmediatamente, buscar conexiones históricas en SIEM y escalar incidente a SOC Nivel 2.**

### 5. [🔴 MALICIOUS] `drop.darknet-loader[.]ru` (URL/Domain)

- **Puntaje de Riesgo SOAR:** `88/100` (AbuseIPDB: `90%` | VirusTotal: `27/90 motores`)
- **Origen / Ubicación:** RU (Russian Federation)
- **ISP / Familia de Malware:** `Malware Dropper Infrastructure`
- **Fuente de Inteligencia:** Offline CTI Threat Feed (VirusTotal + AbuseIPDB Sim)
- **Contexto del Analista:** Dominio de distribución de payloads maliciosos (Dropper) y exfiltración secundaria.
- **Acción SOAR Recomendada:** **BLOQUEAR IOC en Firewall/WAF/Proxy DNS inmediatamente, buscar conexiones históricas en SIEM y escalar incidente a SOC Nivel 2.**

### 6. [🔴 MALICIOUS] `45.155.205[.]109` (IPv4)

- **Puntaje de Riesgo SOAR:** `85/100` (AbuseIPDB: `92%` | VirusTotal: `14/90 motores`)
- **Origen / Ubicación:** RU (Russian Federation)
- **ISP / Familia de Malware:** `Selectel Bulletproof Hosting`
- **Fuente de Inteligencia:** Offline CTI Threat Feed (VirusTotal + AbuseIPDB Sim)
- **Contexto del Analista:** Infraestructura asociada a botnets de Password Spraying y enumeración de credenciales.
- **Acción SOAR Recomendada:** **BLOQUEAR IOC en Firewall/WAF/Proxy DNS inmediatamente, buscar conexiones históricas en SIEM y escalar incidente a SOC Nivel 2.**

### 7. [🟠 SUSPICIOUS] `91.240.118[.]222` (IPv4)

- **Puntaje de Riesgo SOAR:** `58/100` (AbuseIPDB: `65%` | VirusTotal: `6/90 motores`)
- **Origen / Ubicación:** UA / Eastern Europe
- **ISP / Familia de Malware:** `Scanner Cloud ASN`
- **Fuente de Inteligencia:** Offline CTI Threat Feed (VirusTotal + AbuseIPDB Sim)
- **Contexto del Analista:** Escáner automatizado de vulnerabilidades web (Nikto / Nmap) buscando archivos .env y paneles expuestos.
- **Acción SOAR Recomendada:** **Aplicar bloqueo preventivo en WAF/Firewall perimetral y mantener en Watchlist por actividad de reconocimiento/escaneo.**

### 8. [🟢 BENIGN (Falso Positivo)] `8.8.8[.]8` (IPv4)

- **Puntaje de Riesgo SOAR:** `0/100` (AbuseIPDB: `0%` | VirusTotal: `0/90 motores`)
- **Origen / Ubicación:** US (United States)
- **ISP / Familia de Malware:** `Google LLC (Google Public DNS)`
- **Fuente de Inteligencia:** Offline CTI Threat Feed (VirusTotal + AbuseIPDB Sim)
- **Contexto del Analista:** Servidor DNS público legítimo de Google. ¡FALSO POSITIVO! Bloquear esta IP dejaría sin resolución DNS a la empresa.
- **Acción SOAR Recomendada:** **NO BLOQUEAR (Falso Positivo / Infraestructura legítima). Documentar como actividad autorizada en el ticket.**

### 9. [🟢 BENIGN (Falso Positivo)] `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (SHA-256)

- **Puntaje de Riesgo SOAR:** `0/100` (AbuseIPDB: `0%` | VirusTotal: `0/72 motores`)
- **Origen / Ubicación:** Archivo de Sistema (C:\Windows\System32\notepad.exe)
- **ISP / Familia de Malware:** `Microsoft Windows Genuine File (Empty/Clean Hash)`
- **Fuente de Inteligencia:** Offline CTI Threat Feed (VirusTotal + AbuseIPDB Sim)
- **Contexto del Analista:** Hash SHA-256 limpio y verificado. Sin detecciones de malware en VirusTotal.
- **Acción SOAR Recomendada:** **NO BLOQUEAR (Falso Positivo / Infraestructura legítima). Documentar como actividad autorizada en el ticket.**
