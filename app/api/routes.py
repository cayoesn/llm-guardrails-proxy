import time
from typing import Dict
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

# In-memory counter for audit statistics
stats_store = {
    "total_inspections": 0,
    "blocked_attacks": 0,
    "allowed_requests": 0,
    "total_pii_masked": 0
}


@router.post("/guard", response_model=GuardResponse)
def inspect_guard(req: GuardRequest) -> GuardResponse:
    """
    Inspects the user prompt for injections/jailbreaks and sanitizes PII.
    """
    start_time = time.time()
    stats_store["total_inspections"] += 1

    # 1. Prompt Injection / Jailbreak Analysis
    sec_analysis = injection_detector.analyze(req.prompt)

    # 2. PII Sanitization
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

    # 3. Simulated LLM forwarding if auto_forward_llm is True and prompt is safe
    llm_resp = None
    if sec_analysis["is_safe"] and req.auto_forward_llm:
        raw_llm_out = f"Simulated LLM response for query: '{pii_res['sanitized_text']}'"
        # 4. Output moderation
        mod_res = output_moderator.moderate(raw_llm_out)
        if mod_res["is_approved"]:
            # Rehydrate PII in the final response if applicable
            llm_resp = pii_sanitizer.unmask(raw_llm_out, pii_res["pii_map"])
        else:
            llm_resp = "[RESPONSE BLOCKED DUE TO POLICY VIOLATION]"

    elapsed_ms = round((time.time() - start_time) * 1000, 2)

    # 5. Observability logging in Langfuse
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
    Sanitizes PII from text, returning placeholders and a deanonymization map.
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
    Rehydrates text by replacing placeholders with the original PII values.
    """
    unmasked = pii_sanitizer.unmask(req.sanitized_text, req.pii_map)
    return PIIUnmaskResponse(unmasked_text=unmasked)


@router.get("/stats", response_model=GuardStatsResponse)
def get_stats() -> GuardStatsResponse:
    """Returns accumulated security inspection statistics for the proxy."""
    return GuardStatsResponse(**stats_store)


@router.delete("/stats")
def reset_stats() -> Dict[str, str]:
    """Resets accumulated audit statistics."""
    global stats_store
    stats_store = {
        "total_inspections": 0,
        "blocked_attacks": 0,
        "allowed_requests": 0,
        "total_pii_masked": 0
    }
    return {"message": "Audit statistics successfully reset."}
