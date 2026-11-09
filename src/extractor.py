"""
Módulo de Extracción, Refanging y Filtrado de IOCs (Fase 1 del Mini-SOAR).

Conceptos clave de SOC L1 implementados aquí:
1. Refanging: Convertir indicadores neutralizados ('185.220.101[.]45', 'hxxp://') a su forma
   original para poder consultarlos en las APIs de VirusTotal y AbuseIPDB.
2. Filtrado de IPs Privadas (RFC 1918): Separar IPs de la red local ('10.x.x.x', '192.168.x.x',
   '172.16-31.x.x') de las IPs públicas de internet.
3. Extracción de Hashes SHA-256 (64 caracteres hexadecimales): Identificar la huella digital
   única de archivos sospechosos sin importar el nombre que les haya puesto el atacante.
"""

from dataclasses import dataclass, field
import ipaddress
import re
from typing import List


@dataclass
class ExtractedIOCs:
    """Contenedor estructurado de Indicadores de Compromiso extraídos de un ticket."""

    public_ips: List[str] = field(default_factory=list)
    internal_private_ips: List[str] = field(default_factory=list)
    urls_and_domains: List[str] = field(default_factory=list)
    sha256_hashes: List[str] = field(default_factory=list)


IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")
URL_REGEX = re.compile(r"\bhttps?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s\"'<>]*)?", re.IGNORECASE)
DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9\-]+\.)+(?:xyz|ru|com|net|org|io|top|cn|info|biz)\b",
    re.IGNORECASE,
)


def refang_text(text: str) -> str:
    """
    Revierte el 'defanging' en un texto para poder extraer y consultar los IOCs reales.
    Ejemplo: 'hxxp://c2.attacker-domain[.]xyz' -> 'http://c2.attacker-domain.xyz'
    """
    cleaned = re.sub(r"\bhxxps://", "https://", text, flags=re.IGNORECASE)
    cleaned = re.sub(r"\bhxxp://", "http://", cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.replace("[.]", ".").replace("(.)", ".")
    return cleaned


def defang_ioc(ioc: str) -> str:
    """
    Aplica 'defanging' seguro a una IP, dominio o URL antes de escribirla en el reporte.
    """
    defanged = re.sub(r"^http://", "hxxp://", ioc, flags=re.IGNORECASE)
    defanged = re.sub(r"^https://", "hxxps://", defanged, flags=re.IGNORECASE)

    if IPV4_REGEX.fullmatch(defanged):
        parts = defanged.rsplit(".", 1)
        return f"{parts[0]}[.]{parts[1]}"

    return re.sub(r"\.([a-zA-Z]{2,})(/|$)", r"[.]\1\2", defanged)


RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
)


def is_private_or_reserved_ip(ip_str: str) -> bool:
    """
    Verifica si una dirección IPv4 pertenece a los rangos de red interna privada
    RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) o loopback (127.0.0.0/8).
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in RFC1918_NETWORKS)
    except ValueError:
        return True


def extract_iocs_from_text(raw_text: str) -> ExtractedIOCs:
    """
    Recibe el texto crudo de un ticket o correo, aplica refanging, extrae IPs, URLs/dominios
    y hashes SHA-256, y separa automáticamente las IPs internas de las IPs públicas.
    """
    normalized_text = refang_text(raw_text)

    public_ips: List[str] = []
    private_ips: List[str] = []

    for candidate_ip in IPV4_REGEX.findall(normalized_text):
        try:
            ipaddress.ip_address(candidate_ip)
        except ValueError:
            continue

        if is_private_or_reserved_ip(candidate_ip):
            if candidate_ip not in private_ips:
                private_ips.append(candidate_ip)
        else:
            if candidate_ip not in public_ips:
                public_ips.append(candidate_ip)

    sha256_hashes: List[str] = []
    for h in SHA256_REGEX.findall(normalized_text):
        lower_h = h.lower()
        if lower_h not in sha256_hashes:
            sha256_hashes.append(lower_h)

    urls_and_domains: List[str] = []
    for url in URL_REGEX.findall(normalized_text):
        if url not in urls_and_domains:
            urls_and_domains.append(url)

    for domain in DOMAIN_REGEX.findall(normalized_text):
        # Evitar duplicar un dominio que ya es parte de una URL capturada
        if not any(domain.lower() in u.lower() for u in urls_and_domains):
            if domain not in urls_and_domains:
                urls_and_domains.append(domain)

    return ExtractedIOCs(
        public_ips=public_ips,
        internal_private_ips=private_ips,
        urls_and_domains=urls_and_domains,
        sha256_hashes=sha256_hashes,
    )
