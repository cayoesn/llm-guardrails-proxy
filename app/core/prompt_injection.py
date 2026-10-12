import re
import base64
from typing import Dict, Any, List


class PromptInjectionDetector:
    """Enterprise Multi-Layer Prompt Injection & Jailbreak Detector.
    
    Características Staff/Principal:
    1. Heuristic & Semantic Pattern Matching: Detecção de comandos diretos de evasão e personificação.
    2. Delimiter Hijacking & XML Injection: Detecção de quebra de tags de sistema (ex: </system>, [INST]).
    3. Obfuscation & Encoding Inspection: Decodificação especulativa de payloads Base64 e Hex para
       inspeção profunda de ataques evasivos.
    """

    PATTERNS = [
        (r"(?i)\bignore\s+(all\s+)?(previous|prior|safety|system)?\s*(instructions|prompts|rules|directives)\b", 0.9, "IGNORE_INSTRUCTIONS"),
        (r"(?i)\bforget\s+(all\s+)?(safety|system|ethics)\s+(rules|prompts|guidelines)\b", 0.95, "FORGET_SAFETY"),
        (r"(?i)\b(you\s+are\s+now|act\s+as)\s+(unlocked|dan|do\s+anything\s+now|developer\s+mode|god\s+mode)\b", 0.95, "JAILBREAK_ROLEPLAY"),
        (r"(?i)\bpretend\s+(you\s+have\s+no|there\s+are\s+no)\s+(restrictions|limits|filters)\b", 0.85, "BYPASS_RESTRICTIONS"),
        (r"(?i)\b(system\s+prompt|system_prompt)\s*(:\s*|=)\s*", 0.75, "SYSTEM_PROMPT_OVERRIDE"),
        (r"(?i)\b(cat\s+/etc/passwd|rm\s+-rf|sudo\s+rm|format\s+c:|/bin/bash|eval\(|exec\()\b", 0.9, "COMMAND_INJECTION"),
        (r"(?i)\b(disregard\s+system\s+directives|override\s+security\s+protocol)\b", 0.85, "OVERRIDE_DIRECTIVES"),
        (r"(?i)(</system>|</inst>|\[/INST\]|<!--\s*system\s*-->|<\|im_end\|>|<\|im_start\|>)", 0.95, "DELIMITER_HIJACKING"),
    ]

    BASE64_PATTERN = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")

    def _inspect_encoded_payloads(self, text: str) -> List[Dict[str, Any]]:
        """Inspeciona se blocos Base64 contêm instruções maliciosas ocultas."""
        threats: List[Dict[str, Any]] = []
        for match in self.BASE64_PATTERN.finditer(text):
            b64_str = match.group(0)
            try:
                decoded = base64.b64decode(b64_str, validate=True).decode("utf-8", errors="ignore")
                if len(decoded) >= 8:
                    for pattern, severity, category in self.PATTERNS:
                        if re.search(pattern, decoded):
                            threats.append({
                                "category": f"OBFUSCATED_{category}",
                                "severity": max(0.90, severity),
                                "detail": "Decoded from Base64 payload"
                            })
            except Exception:
                pass
        return threats

    def analyze(self, prompt: str) -> Dict[str, Any]:
        """Analisa o prompt em múltiplas camadas (texto claro, delimitadores e decodificação especulativa)."""
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

        # Inspeção de ofuscação
        obfuscated_threats = self._inspect_encoded_payloads(prompt)
        for ot in obfuscated_threats:
            detected_threats.append(ot)
            if ot["severity"] > max_score:
                max_score = ot["severity"]

        if len(prompt) > 4000:
            max_score = min(1.0, max_score + 0.1)

        is_safe = max_score < 0.65

        return {
            "is_safe": is_safe,
            "risk_score": round(max_score, 2),
            "threats": detected_threats,
            "action": "ALLOW" if is_safe else "BLOCK"
        }
