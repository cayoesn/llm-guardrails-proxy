import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class GuardrailsObservability:
    """Security Telemetry and Tracing Manager for Langfuse."""

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
            logger.info("Langfuse Observability Client initialized in Guardrails Proxy.")
        except Exception as e:
            logger.warning(f"Langfuse SDK unavailable. Tracing running in isolated mode: {e}")
            self.client = None

    def trace_guard_evaluation(
        self,
        prompt: str,
        security_analysis: Dict[str, Any],
        pii_analysis: Dict[str, Any],
        duration_ms: float
    ) -> Optional[str]:
        """
        Records a complete security evaluation trace in Langfuse.
        """
        if not self.client:
            return None

        try:
            status = "BLOCKED" if not security_analysis.get("is_safe") else "ALLOWED"
            
            if hasattr(self.client, "trace"):
                trace = self.client.trace(
                    name="guardrails_security_check",
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
                if hasattr(trace, "span"):
                    trace.span(
                        name="prompt_injection_check",
                        input={"prompt_length": len(prompt)},
                        output={
                            "is_safe": security_analysis.get("is_safe"),
                            "risk_score": security_analysis.get("risk_score"),
                            "threats": security_analysis.get("threats")
                        }
                    )
                if hasattr(trace, "score"):
                    trace.score(
                        name="security_risk_score",
                        value=float(security_analysis.get("risk_score", 0.0)),
                        comment=f"Threats detected: {len(security_analysis.get('threats', []))}"
                    )
                return getattr(trace, "id", "demo-guard-trace-id")
            return "demo-guard-trace-id"
        except Exception as e:
            logger.error(f"Error recording guardrails trace in Langfuse: {e}")
            return None


guardrails_obs = GuardrailsObservability()
