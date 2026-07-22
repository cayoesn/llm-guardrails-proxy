import re
from typing import Dict, Any, List


class OutputModerator:
    """Moderador de saída da LLM para conformidade ética e validação de vazamentos."""

    MODERATION_PATTERNS = [
        (r"(?i)\b(system_prompt_secret_key|api_key_sk_\w+|ghp_\w+)\b", "SECRET_KEY_LEAK", 1.0),
        (r"(?i)\b(fuck|shit|bitch|bastard|asshole)\b", "TOXIC_LANGUAGE", 0.8),
        (r"(?i)\bas\s+an\s+ai\s+language\s+model,\s+i\s+cannot\s+verify\s+if\s+this\s+is\s+true\b", "HALLUCINATION_FLAG", 0.5),
        (r"(?i)\b(guarantee\s+100%\s+return\s+on\s+investment|guaranteed\s+profit)\b", "COMPLIANCE_VIOLATION", 0.9)
    ]

    def moderate(self, output_text: str) -> Dict[str, Any]:
        """
        Valida a resposta gerada pela LLM contra regras de moderação.
        """
        violations: List[Dict[str, Any]] = []
        max_severity = 0.0

        for pattern, category, severity in self.MODERATION_PATTERNS:
            if re.search(pattern, output_text):
                violations.append({
                    "category": category,
                    "severity": severity
                })
                if severity > max_severity:
                    max_severity = severity

        is_approved = max_severity < 0.7

        return {
            "is_approved": is_approved,
            "severity_score": round(max_severity, 2),
            "violations": violations,
            "action": "PASS" if is_approved else "REDACT_OR_BLOCK"
        }
