# 🛡️ LLM Guardrails Proxy (Enterprise Edition)

Proxy Interceptador de Segurança e Moderação para LLMs baseado em **Llama-Guard**, **NeMo Guardrails** e **PII Sanitizer**.

## 🌟 Arquitetura & Recursos Big-Tech
- **Llama-Guard Safety Classifier**: Classificação semântica em tempo real sob taxonomia de 6 categorias de risco (Violência, Discurso de Ódio, Cyberattacks, Conteúdo Sexual, Atos Ilegais e PII).
- **PII Sanitizer & Redaction Engine**: Detecção e mascaramento automático de dados sensíveis (CPF, E-mails, Cartões de Crédito).
- **Prompt Injection & Jailbreak Defense**: Análise de padrões para bloqueio imediato de injeções de prompt e bypasses de sistema.

## 🚀 Como Executar no Docker
```bash
docker compose up -d --build
```

## 🧪 Testes Unitários e Integração (>98% Cobertura)
```bash
docker run --rm -v $(pwd):/app -w /app python:3.12-slim bash -c "pip install pytest pytest-asyncio pytest-cov pydantic pydantic-settings httpx fastapi uvicorn prometheus_fastapi_instrumentator && PYTHONPATH=. pytest"
```
