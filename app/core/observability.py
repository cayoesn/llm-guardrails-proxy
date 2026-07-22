import logging
import time
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class GuardrailsObservability:
    """Gerenciador de Telemetria e Tracing de Segurança no Langfuse."""

    def __init__(self) -> None:
        self.client = None
        self._init_client()

    def _init_client(self) -> None:
        try:
            from langfuse import Langfuse
            from app.config import settings
            self.client = Langfuse(
                public_key=settings.LANGFUSE_PUBLIC_KEY,
                secret_key=settings.LANGFUSE_SECRET_KEY,
                host=settings.LANGFUSE_HOST
            )
            logger.info("Langfuse Observability Client inicializado no Guardrails Proxy.")
        except Exception as e:
            logger.warning(f"Langfuse SDK indisponível. Tracing operando em modo isolado: {e}")
            self.client = None

    def trace_guard_evaluation(
        self,
        prompt: str,
        security_analysis: Dict[str, Any],
        pii_analysis: Dict[str, Any],
        duration_ms: float
    ) -> Optional[str]:
        """
        Registra uma avaliação de segurança completa no Langfuse.
        """
        if not self.client:
            return None

        try:
            trace_name = "guardrails_security_check"
            status = "BLOCKED" if not security_analysis.get("is_safe") else "ALLOWED"
            
            trace = self.client.trace(
                name=trace_name,
                metadata={
                    "risk_score": security_analysis.get("risk_score"),
                    "action": security_analysis.get("action"),
                    "has_pii": pii_analysis.get("has_pii"),
                    "total_masked_pii": pii_analysis.get("total_masked"),
                    "status": status,
                    "duration_ms": duration_ms
                },
                tags=["security", "guardrails", status]
            )

            # Span de Injeção de Prompt
            trace.span(
                name="prompt_injection_check",
                input={"prompt_length": len(prompt)},
                output={
                    "is_safe": security_analysis.get("is_safe"),
                    "risk_score": security_analysis.get("risk_score"),
                    "threats": security_analysis.get("threats")
                }
            )

            # Span de PII Sanitization
            trace.span(
                name="pii_sanitization_check",
                input={"has_pii": pii_analysis.get("has_pii")},
                output={
                    "entities_count": pii_analysis.get("entities_count"),
                    "total_masked": pii_analysis.get("total_masked")
                }
            )

            # Registra Score de Risco de Segurança
            trace.score(
                name="security_risk_score",
                value=float(security_analysis.get("risk_score", 0.0)),
                comment=f"Threats detected: {len(security_analysis.get('threats', []))}"
            )

            return getattr(trace, "id", "demo-guard-trace-id")
        except Exception as e:
            logger.error(f"Erro ao registrar trace de guardrails no Langfuse: {e}")
            return None


guardrails_obs = GuardrailsObservability()
