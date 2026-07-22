from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configurações globais do Guardrails Proxy."""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    APP_NAME: str = "LLM Guardrails Proxy"
    ENV: str = "development"
    DEBUG: bool = True

    # Thresholds de Segurança
    MAX_RISK_SCORE: float = 0.65  # Bloqueia se score de ataque >= 0.65

    # Credenciais do Langfuse (Observabilidade)
    LANGFUSE_PUBLIC_KEY: str = "pk-lf-demo"
    LANGFUSE_SECRET_KEY: str = "sk-lf-demo"
    LANGFUSE_HOST: str = "http://localhost:3000"


settings = Settings()
