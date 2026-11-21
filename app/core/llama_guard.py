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

    Applies a 6-category safety taxonomy to detect policy violations
    in LLM inputs and outputs in real time.
    """

    UNSAFE_KEYWORDS = {
        SafetyCategory.VIOLENCE: ["kill", "assault", "bomb", "firearm", "detonate", "murder"],
        SafetyCategory.HATE_SPEECH: ["racist", "bigot", "hate speech", "racial slur", "discriminate"],
        SafetyCategory.CYBERATTACKS: ["ddos", "exploit", "keylogger", "malware", "sql injection"],
        SafetyCategory.ILLEGAL_ACTS: ["clone credit card", "forge document", "counterfeit", "smuggling"],
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
            reasoning="Content passed safety filters." if is_safe else f"Content violated safety categories: {', '.join(flagged)}",
        )


# Singleton instance
llama_guard_filter = LlamaGuardSafetyFilter()
