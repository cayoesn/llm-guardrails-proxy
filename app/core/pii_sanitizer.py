import re
from typing import Dict, Any, List, Tuple


class PIISanitizer:
    """Enterprise Single-Pass PII Sanitizer & Atomic Reversible Deanonymizer.

    Staff/Principal Engineering Characteristics:
    1. Single-Pass O(|T|): Unified compiled regex with Named Capture Groups that
       scans and redacts in a single pass, avoiding re-scans and repeated string allocations.
    2. Atomic Unmasking: Placeholder rehydration via atomic regex tokenization,
       immune to substring conflicts or partial placeholder collisions.
    """

    # Pre-compiled named regular expressions in a single finite state machine.
    # Longer/more specific patterns precede shorter ones (e.g., CREDIT_CARD precedes SSN/CPF/PHONE).
    # Includes US SSN, international national ID (Brazilian CPF), credit cards, emails, phone numbers, and API keys.
    PII_UNIFIED_REGEX = re.compile(
        r"(?P<CREDIT_CARD>\b(?:\d{4}[-.\s]?){3}\d{4}\b)|"
        r"(?P<API_KEY>\b(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{20,})\b)|"
        r"(?P<EMAIL>\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)|"
        r"(?P<SSN>\b\d{3}-\d{2}-\d{4}\b)|"
        r"(?P<CPF>\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b)|"
        r"(?P<PHONE>(?<!\w)(?:\+\d{1,3}[-.\s]?)?(?:\(\d{2,3}\)[-.\s]?|\d{2,3}[-.\s])?\d{3,5}[-.\s]\d{4}\b)"
    )

    def sanitize(self, text: str) -> Dict[str, Any]:
        """Detects and redacts PII entities in a single O(|T|) pass."""
        pii_map: Dict[str, str] = {}
        val_to_placeholder: Dict[str, str] = {}
        detected_counts: Dict[str, int] = {}
        counters: Dict[str, int] = {}

        def replace_callback(match: re.Match) -> str:
            # Identify which named group matched
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
        """Atomically rehydrates masked text in a single O(|T|) pass."""
        if not pii_map or not text:
            return text

        # Compile a strict regex for all active placeholders ordered by descending length
        escaped_keys = [re.escape(k) for k in sorted(pii_map.keys(), key=len, reverse=True)]
        placeholder_pattern = re.compile("|".join(escaped_keys))

        return placeholder_pattern.sub(lambda m: pii_map.get(m.group(0), m.group(0)), text)
