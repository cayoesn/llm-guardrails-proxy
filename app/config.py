from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Global configuration settings for the Guardrails Proxy."""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    APP_NAME: str = "LLM Guardrails Proxy"
    ENV: str = "development"
    DEBUG: bool = True

    # Security Thresholds
    MAX_RISK_SCORE: float = 0.65  # Block requests if attack risk score >= 0.65

    # Langfuse Credentials (Observability)
    LANGFUSE_PUBLIC_KEY: str = "pk-lf-demo"
    LANGFUSE_SECRET_KEY: str = "sk-lf-demo"
    LANGFUSE_HOST: str = "http://localhost:3000"


settings = Settings()
