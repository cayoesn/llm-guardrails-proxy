import re
from typing import Dict, Any, List, Tuple


class PIISanitizer:
    """Enterprise Single-Pass PII Sanitizer & Atomic Reversible Deanonymizer.
    
    Características Staff/Principal:
    1. Single-Pass O(|T|): Regex unificada compilada com Named Capture Groups que realiza
       a varredura e substituição em um único passe, evitando re-scans e mutações de string.
    2. Atomic Unmasking: Reidratação de placeholders através de tokenização atômica regex,
       imune a conflitos de substring ou colisões parciais.
    """

    # Expressões regulares nomeadas e pré-compiladas em uma única máquina de estados
    # Padrões mais longos/específicos precedem padrões curtos (CREDIT_CARD precede PHONE)
    PII_UNIFIED_REGEX = re.compile(
        r"(?P<CPF>\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b)|"
        r"(?P<EMAIL>\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)|"
        r"(?P<CREDIT_CARD>\b(?:\d{4}[-.\s]?){3}\d{4}\b)|"
        r"(?P<PHONE>\b(?:\+?55\s?)?(?:\(?\d{2}\)?\s?)?(?:9?\d{4}[-.\s]?\d{4})\b)"
    )

    def sanitize(self, text: str) -> Dict[str, Any]:
        """Detecta e ofusca entidades PII em um único passe O(|T|)."""
        pii_map: Dict[str, str] = {}
        val_to_placeholder: Dict[str, str] = {}
        detected_counts: Dict[str, int] = {}
        counters: Dict[str, int] = {}

        def replace_callback(match: re.Match) -> str:
            # Identifica qual grupo nomeado casou
            for pii_type, val in match.groupdict().items():
                if val is not None:
                    detected_counts[pii_type] = detected_counts.get(pii_type, 0) + 1
                    
                    if val in val_to_placeholder:
                        return val_to_placeholder[val]
                    
                    counters[pii_type] = counters.get(pii_type, 0) + 1
                    placeholder = f"[{pii_type}_{counters[pii_type]}]"
                    val_to_placeholder[val] = placeholder
                    pii_map[placeholder] = val
                    return placeholder
            return match.group(0)

        sanitized_text = self.PII_UNIFIED_REGEX.sub(replace_callback, text)

        return {
            "sanitized_text": sanitized_text,
            "pii_map": pii_map,
            "has_pii": len(pii_map) > 0,
            "entities_count": detected_counts,
            "total_masked": len(pii_map)
        }

    def unmask(self, text: str, pii_map: Dict[str, str]) -> str:
        """Reidrata o texto de forma atômica em único passe O(|T|)."""
        if not pii_map or not text:
            return text

        # Compila regex estrita para todos os placeholders ativos ordenados pelo tamanho decrescente
        escaped_keys = [re.escape(k) for k in sorted(pii_map.keys(), key=len, reverse=True)]
        placeholder_pattern = re.compile("|".join(escaped_keys))

        return placeholder_pattern.sub(lambda m: pii_map.get(m.group(0), m.group(0)), text)
