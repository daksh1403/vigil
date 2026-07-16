"""Application configuration via pydantic-settings."""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # App
    env: Literal["development", "staging", "production"] = "development"
    app_name: str = "vigil"
    secret_key: str = "change-me"
    api_v1_prefix: str = "/api/v1"
    backend_cors_origins: str = "http://localhost:3000"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # Database
    postgres_user: str = "vigil"
    postgres_password: str = "vigil"
    postgres_db: str = "vigil"
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    database_url: str | None = None

    # Redis / Celery
    redis_url: str = "redis://redis:6379/0"
    celery_broker_url: str = "redis://redis:6379/1"
    celery_result_backend: str = "redis://redis:6379/2"
    celery_worker_concurrency: int = 4

    # Auth bootstrap
    first_superuser_email: str = "admin@vigil.dev"
    first_superuser_password: str = "vigiladmin"

    # Encryption
    encryption_key: str = ""

    # AI / LLM
    ollama_base_url: str = "http://ollama:11434"
    ollama_model: str = "tinyllama"
    ollama_embed_model: str = "nomic-embed-text"
    llm_enabled: bool = True
    llm_timeout: int = 120
    llm_fallback: bool = True

    # AI triage thresholds
    dedup_similarity_threshold: float = 0.88
    fp_model_path: str = "ml/registry/fp_isoforest.joblib"
    risk_weight_cvss: float = 0.4
    risk_weight_epss: float = 0.25
    risk_weight_exploitability: float = 0.15
    risk_weight_asset: float = 0.1
    risk_weight_fp: float = 0.1

    # Scanners
    scanner_timeout: int = 600
    scanner_rate_limit: int = 150
    nuclei_templates_dir: str = "/data/nuclei-templates"
    scanner_restrict_local_net: bool = True

    # Observability
    prometheus_enabled: bool = True
    log_level: str = "INFO"
    sentry_dsn: str = ""

    @computed_field  # type: ignore[misc]
    @property
    def sqlalchemy_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.backend_cors_origins.split(",") if o.strip()]

    @property
    def is_dev(self) -> bool:
        return self.env == "development"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
