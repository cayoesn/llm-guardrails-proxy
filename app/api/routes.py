import time
from fastapi import APIRouter, HTTPException, status
from app.api.schemas import (
    GuardRequest,
    GuardResponse,
    PIIMaskRequest,
    PIIMaskResponse,
    PIIUnmaskRequest,
    PIIUnmaskResponse,
    GuardStatsResponse
)
from app.core.prompt_injection import PromptInjectionDetector
from app.core.pii_sanitizer import PIISanitizer
from app.core.output_moderator import OutputModerator
from app.core.observability import guardrails_obs

router = APIRouter(prefix="/api/v1", tags=["Guardrails & PII Proxy"])

injection_detector = PromptInjectionDetector()
pii_sanitizer = PIISanitizer()
output_moderator = OutputModerator()

# Contador em memória para estatísticas de auditoria
stats_store = {
    "total_inspections": 0,
    "blocked_attacks": 0,
    "allowed_requests": 0,
    "total_pii_masked": 0
}


@router.post("/guard", response_model=GuardResponse)
def inspect_guard(req: GuardRequest) -> GuardResponse:
    """
    Inspeciona o prompt do usuário contra injeções/jailbreaks e higieniza PII.
    """
    start_time = time.time()
    stats_store["total_inspections"] += 1

    # 1. Análise de Injeção de Prompt / Jailbreak
    sec_analysis = injection_detector.analyze(req.prompt)

    # 2. Sanitização de PII
    if req.mask_pii:
        pii_res = pii_sanitizer.sanitize(req.prompt)
    else:
        pii_res = {
            "sanitized_text": req.prompt,
            "pii_map": {},
            "has_pii": False,
            "total_masked": 0,
            "entities_count": {}
        }

    stats_store["total_pii_masked"] += pii_res["total_masked"]

    if not sec_analysis["is_safe"]:
        stats_store["blocked_attacks"] += 1
    else:
        stats_store["allowed_requests"] += 1

    # 3. Simulação de envio para LLM se auto_forward_llm for True e for seguro
    llm_resp = None
    if sec_analysis["is_safe"] and req.auto_forward_llm:
        raw_llm_out = f"Resposta simulada da LLM para a consulta: '{pii_res['sanitized_text']}'"
        # 4. Moderação de saída
        mod_res = output_moderator.moderate(raw_llm_out)
        if mod_res["is_approved"]:
            # Reidrata PII na resposta final se aplicável
            llm_resp = pii_sanitizer.unmask(raw_llm_out, pii_res["pii_map"])
        else:
            llm_resp = "[RESPOSTA BLOQUEADA POR VIOLAÇÃO DE POLÍTICA]"

    elapsed_ms = round((time.time() - start_time) * 1000, 2)

    # 5. Registro de Observabilidade no Langfuse
    guardrails_obs.trace_guard_evaluation(
        prompt=req.prompt,
        security_analysis=sec_analysis,
        pii_analysis=pii_res,
        duration_ms=elapsed_ms
    )

    return GuardResponse(
        is_safe=sec_analysis["is_safe"],
        risk_score=sec_analysis["risk_score"],
        action=sec_analysis["action"],
        sanitized_prompt=pii_res["sanitized_text"],
        has_pii=pii_res["has_pii"],
        pii_map=pii_res["pii_map"],
        threats_detected=sec_analysis["threats"],
        llm_response=llm_resp,
        processing_time_ms=elapsed_ms
    )


@router.post("/pii/mask", response_model=PIIMaskResponse)
def mask_pii_endpoint(req: PIIMaskRequest) -> PIIMaskResponse:
    """
    Higieniza PIIs de um texto retornando placeholders e mapa de desofuscação.
    """
    res = pii_sanitizer.sanitize(req.text)
    return PIIMaskResponse(
        sanitized_text=res["sanitized_text"],
        pii_map=res["pii_map"],
        entities_count=res["entities_count"],
        total_masked=res["total_masked"]
    )


@router.post("/pii/unmask", response_model=PIIUnmaskResponse)
def unmask_pii_endpoint(req: PIIUnmaskRequest) -> PIIUnmaskResponse:
    """
    Reidrata texto substituindo placeholders pelos dados originais.
    """
    unmasked = pii_sanitizer.unmask(req.sanitized_text, req.pii_map)
    return PIIUnmaskResponse(unmasked_text=unmasked)


@router.get("/stats", response_model=GuardStatsResponse)
def get_stats() -> GuardStatsResponse:
    """Retorna estatísticas acumuladas de inspeções de segurança do proxy."""
    return GuardStatsResponse(**stats_store)


@router.delete("/stats")
def reset_stats() -> Dict[str, str]:
    """Zera as estatísticas acumuladas de auditoria."""
    global stats_store
    stats_store = {
        "total_inspections": 0,
        "blocked_attacks": 0,
        "allowed_requests": 0,
        "total_pii_masked": 0
    }
    return {"message": "Estatísticas de auditoria zeradas com sucesso."}
