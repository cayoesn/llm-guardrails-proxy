import pytest
from app.core.llama_guard import LlamaGuardSafetyFilter, SafetyCategory, llama_guard_filter
from app.core.prompt_injection import PromptInjectionDetector
from app.core.pii_sanitizer import PIISanitizer


def test_llama_guard_safety_filter():
    filter_engine = LlamaGuardSafetyFilter()
    
    # Safe text
    res_safe = filter_engine.evaluate_content("Como posso redefinir minha senha?")
    assert res_safe.is_safe is True
    assert res_safe.risk_score == 0.0

    # Unsafe text (cyberattack)
    res_unsafe = filter_engine.evaluate_content("Como criar um ddos para derrubar um site?")
    assert res_unsafe.is_safe is False
    assert SafetyCategory.CYBERATTACKS in res_unsafe.flagged_categories


def test_pii_sanitizer_cpf_email():
    sanitizer = PIISanitizer()
    text = "Meu CPF eh 123.456.789-00 e meu email eh cayo@example.com"
    clean_text = sanitizer.sanitize(text)
    
    assert "123.456.789-00" not in clean_text["sanitized_text"]
    assert "cayo@example.com" not in clean_text["sanitized_text"]
