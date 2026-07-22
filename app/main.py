from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.api.routes import router

app = FastAPI(
    title=settings.APP_NAME,
    description="Enterprise Security, Prompt Injection Guardrails and PII Sanitization Proxy for LLMs",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/health", tags=["Health Check"])
def health_check():
    """Health check endpoint para monitoramento de infraestrutura."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "env": settings.ENV,
        "max_risk_score_threshold": settings.MAX_RISK_SCORE
    }
