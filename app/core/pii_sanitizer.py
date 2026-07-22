import re
from typing import Dict, Any, List, Tuple


class PIISanitizer:
    """Ofuscador e Desofuscador de Dados Pessoais Sensíveis (PII)."""

    PII_PATTERNS = [
        ("CPF", r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"),
        ("EMAIL", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        ("PHONE", r"\b(?:\+?55\s?)?(?:\(?\d{2}\)?\s?)?(?:9?\d{4}[-.\s]?\d{4})\b"),
        ("CREDIT_CARD", r"\b(?:\d{4}[-.\s]?){3}\d{4}\b")
    ]

    def sanitize(self, text: str) -> Dict[str, Any]:
        """
        Detecta e ofusca entidades PII, substituindo por placeholders [TIPO_INDEX].
        Retorna o texto higienizado e o mapa de reversão.
        """
        sanitized_text = text
        pii_map: Dict[str, str] = {}
        detected_counts: Dict[str, int] = {}
        counters: Dict[str, int] = {}

        for pii_type, pattern in self.PII_PATTERNS:
            matches = list(re.finditer(pattern, sanitized_text))
            for match in reversed(matches):
                val = match.group(0)
                # Verifica se ja temos um placeholder para esse valor exato
                existing_key = None
                for k, v in pii_map.items():
                    if v == val:
                        existing_key = k
                        break

                if not existing_key:
                    counters[pii_type] = counters.get(pii_type, 0) + 1
                    placeholder = f"[{pii_type}_{counters[pii_type]}]"
                    pii_map[placeholder] = val
                else:
                    placeholder = existing_key

                detected_counts[pii_type] = detected_counts.get(pii_type, 0) + 1
                start, end = match.span()
                sanitized_text = sanitized_text[:start] + placeholder + sanitized_text[end:]

        return {
            "sanitized_text": sanitized_text,
            "pii_map": pii_map,
            "has_pii": len(pii_map) > 0,
            "entities_count": detected_counts,
            "total_masked": len(pii_map)
        }

    def unmask(self, text: str, pii_map: Dict[str, str]) -> str:
        """
        Reidrata o texto substituindo os placeholders [TIPO_INDEX] pelos valores originais.
        """
        unmasked_text = text
        for placeholder, original_val in pii_map.items():
            unmasked_text = unmasked_text.replace(placeholder, original_val)
        return unmasked_text
