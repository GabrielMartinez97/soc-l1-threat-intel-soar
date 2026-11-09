"""
Pruebas unitarias para el Mini-SOAR de Threat Intelligence (SOC L1).
"""

import unittest

from src.enricher import enrich_all_iocs
from src.extractor import extract_iocs_from_text, is_private_or_reserved_ip, refang_text


class TestThreatIntelSOAR(unittest.TestCase):
    def test_refang_and_rfc1918_filtering(self) -> None:
        sample = (
            "Host interno 10.10.20.15 y 192.168.1.50 atacados desde 185.220.101[.]45 "
            "y DNS 8.8.8.8 con C2 hxxp://c2.attacker-domain[.]xyz/collect"
        )
        self.assertIn("http://c2.attacker-domain.xyz/collect", refang_text(sample))
        self.assertTrue(is_private_or_reserved_ip("10.10.20.15"))
        self.assertTrue(is_private_or_reserved_ip("192.168.1.50"))
        self.assertFalse(is_private_or_reserved_ip("185.220.101.45"))

        extracted = extract_iocs_from_text(sample)
        self.assertEqual(extracted.internal_private_ips, ["10.10.20.15", "192.168.1.50"])
        self.assertIn("185.220.101.45", extracted.public_ips)
        self.assertIn("8.8.8.8", extracted.public_ips)

    def test_ransomware_hash_and_google_dns_verdicts(self) -> None:
        sample = (
            "IP: 8.8.8.8 | WannaCry SHA256: "
            "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"
        )
        extracted = extract_iocs_from_text(sample)
        enriched = enrich_all_iocs(extracted)
        by_ioc = {item.ioc_value: item for item in enriched}

        self.assertEqual(by_ioc["8.8.8.8"].verdict, "BENIGN")
        self.assertEqual(
            by_ioc["24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"].verdict,
            "MALICIOUS",
        )


if __name__ == "__main__":
    unittest.main()
