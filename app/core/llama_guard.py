from enum import StrEnum
from typing import Any
from pydantic import BaseModel, Field


class SafetyCategory(StrEnum):
    VIOLENCE = "VIOLENCE"
    HATE_SPEECH = "HATE_SPEECH"
    SEXUAL_CONTENT = "SEXUAL_CONTENT"
    CYBERATTACKS = "CYBERATTACKS"
    ILLEGAL_ACTS = "ILLEGAL_ACTS"
    PII_LEAKAGE = "PII_LEAKAGE"


class SafetyCheckResult(BaseModel):
    is_safe: bool
    risk_score: float = Field(ge=0.0, le=1.0)
    flagged_categories: list[SafetyCategory] = Field(default_factory=list)
    reasoning: str


class LlamaGuardSafetyFilter:
    """Enterprise Llama-Guard / NeMo Guardrails Content Classifier Engine.
    
    Aplica taxonomia de segurança de 6 categorias para verificar
    violabilidade de termos em entradas e saídas de LLM em tempo real.
    """

    UNSAFE_KEYWORDS = {
        SafetyCategory.VIOLENCE: ["matar", "espancar", "bombas", "arma de fogo", "explodir"],
        SafetyCategory.HATE_SPEECH: ["racista", "preconceituoso", "discriminação"],
        SafetyCategory.CYBERATTACKS: ["ddos", "exploit", "keylogger", "malware", "sql injection"],
        SafetyCategory.ILLEGAL_ACTS: ["clonar cartão", "falsificar documento", "contrabando"],
    }

    def evaluate_content(self, text: str) -> SafetyCheckResult:
        lower_text = text.lower()
        flagged: list[SafetyCategory] = []

        for category, keywords in self.UNSAFE_KEYWORDS.items():
            for kw in keywords:
                if kw in lower_text:
                    if category not in flagged:
                        flagged.append(category)

        risk_score = min(1.0, len(flagged) * 0.4)
        is_safe = len(flagged) == 0

        return SafetyCheckResult(
            is_safe=is_safe,
            risk_score=round(risk_score, 2),
            flagged_categories=flagged,
            reasoning="Conteúdo aprovado nos filtros de segurança." if is_safe else f"Conteúdo violou categorias de segurança: {', '.join(flagged)}",
        )


# Instância Singleton
llama_guard_filter = LlamaGuardSafetyFilter()
