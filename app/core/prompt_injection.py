import re
from typing import Dict, Any, List


class PromptInjectionDetector:
    """Detector semântico e baseado em regras de ataques de Prompt Injection e Jailbreaks."""

    PATTERNS = [
        (r"(?i)\bignore\s+(all\s+)?(previous|prior)\s+(instructions|prompts|rules)\b", 0.9, "IGNORE_INSTRUCTIONS"),
        (r"(?i)\bforget\s+(all\s+)?(safety|system|ethics)\s+(rules|prompts|guidelines)\b", 0.95, "FORGET_SAFETY"),
        (r"(?i)\b(you\s+are\s+now|act\s+as)\s+(unlocked|dan|do\s+anything\s+now|developer\s+mode|god\s+mode)\b", 0.95, "JAILBREAK_ROLEPLAY"),
        (r"(?i)\bpretend\s+(you\s+have\s+no|there\s+are\s+no)\s+(restrictions|limits|filters)\b", 0.85, "BYPASS_RESTRICTIONS"),
        (r"(?i)\b(system\s+prompt|system_prompt)\s*(:\s*|=)\s*", 0.75, "SYSTEM_PROMPT_OVERRIDE"),
        (r"(?i)\b(cat\s+/etc/passwd|rm\s+-rf|sudo\s+rm|format\s+c:|/bin/bash|eval\(|exec\()\b", 0.9, "COMMAND_INJECTION"),
        (r"(?i)\b(disregard\s+system\s+directives|override\s+security\s+protocol)\b", 0.85, "OVERRIDE_DIRECTIVES"),
    ]

    def analyze(self, prompt: str) -> Dict[str, Any]:
        """
        Analisa o prompt em busca de injeções de prompt ou jailbreaks.
        Retorna score de risco, se é seguro e regras violadas.
        """
        detected_threats: List[Dict[str, Any]] = []
        max_score = 0.0

        for pattern, severity, category in self.PATTERNS:
            if re.search(pattern, prompt):
                detected_threats.append({
                    "category": category,
                    "severity": severity
                })
                if severity > max_score:
                    max_score = severity

        # Risco marginal por repetição de caracteres suspeitos ou tamanho extremo
        if len(prompt) > 4000:
            max_score = min(1.0, max_score + 0.1)

        is_safe = max_score < 0.65

        return {
            "is_safe": is_safe,
            "risk_score": round(max_score, 2),
            "threats": detected_threats,
            "action": "ALLOW" if is_safe else "BLOCK"
        }
