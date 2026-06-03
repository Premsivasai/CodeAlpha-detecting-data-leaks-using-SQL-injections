from pydantic_settings import BaseSettings
from typing import Optional, List
import os


class Settings(BaseSettings):
    PROJECT_NAME: str = "SecureShield - SQL Injection Detection System"
    VERSION: str = "2.0.0"
    API_V1_PREFIX: str = "/api/v1"

    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://postgres:postgres@localhost:5432/secureshield"
    )

    DATABASE_POOL_SIZE: int = int(os.getenv("DATABASE_POOL_SIZE", "20"))
    DATABASE_MAX_OVERFLOW: int = int(os.getenv("DATABASE_MAX_OVERFLOW", "40"))

    SECRET_KEY: str = os.getenv(
        "SECRET_KEY",
        "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    ENCRYPTION_KEY: str = os.getenv(
        "ENCRYPTION_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    )

    ENCRYPTION_VAULT_URL: Optional[str] = os.getenv("ENCRYPTION_VAULT_URL")
    ENCRYPTION_VAULT_TOKEN: Optional[str] = os.getenv("ENCRYPTION_VAULT_TOKEN")
    ENCRYPTION_USE_HSM: bool = os.getenv("ENCRYPTION_USE_HSM", "false").lower() == "true"

    ALLOWED_HOSTS: list = ["*"]

    CORS_ORIGINS: list = [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
    ]

    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    RATE_LIMIT_PER_MINUTE: int = 60

    RATE_LIMIT_STORAGE: str = os.getenv("RATE_LIMIT_STORAGE", "redis")

    AI_MODEL_PATH: str = os.getenv("AI_MODEL_PATH", "./models/sql_injection_model.pkl")
    AI_MODEL_VERSION: str = os.getenv("AI_MODEL_VERSION", "2.0.0")

    AI_INFERENCE_SERVICE_URL: Optional[str] = os.getenv("AI_INFERENCE_SERVICE_URL")
    AI_INFERENCE_TIMEOUT: int = int(os.getenv("AI_INFERENCE_TIMEOUT", "30"))

    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    MULTI_TENANT_ENABLED: bool = os.getenv("MULTI_TENANT_ENABLED", "true").lower() == "true"
    TENANT_ISOLATION_ENABLED: bool = os.getenv("TENANT_ISOLATION_ENABLED", "true").lower() == "true"

    RABBITMQ_URL: str = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
    RABBITMQ_VHOST: str = os.getenv("RABBITMQ_VHOST", "/")

    CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL", "amqp://guest:guest@localhost:5672/")
    CELERY_RESULT_BACKEND: str = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/1")

    KAFKA_BOOTSTRAP_SERVERS: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    KAFKA_SECURITY_PROTOCOL: str = os.getenv("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")

    OPENTELEMETRY_ENABLED: bool = os.getenv("OPENTELEMETRY_ENABLED", "false").lower() == "true"
    OPENTELEMETRY_ENDPOINT: str = os.getenv("OPENTELEMETRY_ENDPOINT", "http://localhost:4317")
    OPENTELEMETRY_SERVICE_NAME: str = os.getenv("OPENTELEMETRY_SERVICE_NAME", "secureshield-backend")

    JAEGER_ENABLED: bool = os.getenv("JAEGER_ENABLED", "false").lower() == "true"
    JAEGER_HOST: str = os.getenv("JAEGER_HOST", "localhost")
    JAEGER_PORT: int = int(os.getenv("JAEGER_PORT", "6831"))

    SPLUNK_URL: Optional[str] = os.getenv("SPLUNK_URL")
    SPLUNK_TOKEN: Optional[str] = os.getenv("SPLUNK_TOKEN")
    SPLUNK_INDEX: str = os.getenv("SPLUNK_INDEX", "secureshield")

    AZURE_SENTINEL_ENABLED: bool = os.getenv("AZURE_SENTINEL_ENABLED", "false").lower() == "true"
    AZURE_SENTINEL_WORKSPACE_ID: Optional[str] = os.getenv("AZURE_SENTINEL_WORKSPACE_ID")
    AZURE_SENTINEL_KEY: Optional[str] = os.getenv("AZURE_SENTINEL_KEY")

    QRADAR_ENABLED: bool = os.getenv("QRADAR_ENABLED", "false").lower() == "true"
    QRADAR_HOST: Optional[str] = os.getenv("QRADOR_HOST")
    QRADAR_PORT: int = int(os.getenv("QRADAR_PORT", "514"))

    ALIENVAULT_ENABLED: bool = os.getenv("ALIENVAULT_ENABLED", "false").lower() == "true"
    ALIENVAULT_API_KEY: Optional[str] = os.getenv("ALIENVAULT_API_KEY")

    ABUSEIPDB_ENABLED: bool = os.getenv("ABUSEIPDB_ENABLED", "false").lower() == "true"
    ABUSEIPDB_API_KEY: Optional[str] = os.getenv("ABUSEIPDB_API_KEY")

    VIRUSTOTAL_ENABLED: bool = os.getenv("VIRUSTOTAL_ENABLED", "false").lower() == "true"
    VIRUSTOTAL_API_KEY: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY")

    MISP_ENABLED: bool = os.getenv("MISP_ENABLED", "false").lower() == "true"
    MISP_URL: Optional[str] = os.getenv("MISP_URL")
    MISP_API_KEY: Optional[str] = os.getenv("MISP_API_KEY")

    KONG_URL: str = os.getenv("KONG_URL", "http://localhost:8001")
    TRAEFIK_ENABLED: bool = os.getenv("TRAEFIK_ENABLED", "false").lower() == "true"

    ZERO_TRUST_ENABLED: bool = os.getenv("ZERO_TRUST_ENABLED", "false").lower() == "true"
    DEVICE_FINGERPRINT_ENABLED: bool = os.getenv("DEVICE_FINGERPRINT_ENABLED", "true").lower() == "true"
    BEHAVIORAL_ANALYTICS_ENABLED: bool = os.getenv("BEHAVIORAL_ANALYTICS_ENABLED", "true").lower() == "true"
    ADAPTIVE_MFA_ENABLED: bool = os.getenv("ADAPTIVE_MFA_ENABLED", "true").lower() == "true"

    SESSION_RISK_SCORING_ENABLED: bool = os.getenv("SESSION_RISK_SCORING_ENABLED", "true").lower() == "true"
    TRUST_SCORE_THRESHOLD: float = float(os.getenv("TRUST_SCORE_THRESHOLD", "0.5"))

    STRIPE_ENABLED: bool = os.getenv("STRIPE_ENABLED", "false").lower() == "true"
    STRIPE_API_KEY: Optional[str] = os.getenv("STRIPE_API_KEY")
    STRIPE_WEBHOOK_SECRET: Optional[str] = os.getenv("STRIPE_WEBHOOK_SECRET")

    BILLING_CYCLE_DAYS: int = int(os.getenv("BILLING_CYCLE_DAYS", "30"))
    DEFAULT_API_QUOTA: int = int(os.getenv("DEFAULT_API_QUOTA", "10000"))
    DEFAULT_STORAGE_QUOTA_MB: int = int(os.getenv("DEFAULT_STORAGE_QUOTA_MB", "1000"))

    MLFLOW_ENABLED: bool = os.getenv("MLFLOW_ENABLED", "false").lower() == "true"
    MLFLOW_TRACKING_URI: Optional[str] = os.getenv("MLFLOW_TRACKING_URI")
    MLFLOW_EXPERIMENT_NAME: str = os.getenv("MLFLOW_EXPERIMENT_NAME", "secureshield")

    SENTRY_DSN: Optional[str] = os.getenv("SENTRY_DSN")
    SENTRY_ENVIRONMENT: str = os.getenv("SENTRY_ENVIRONMENT", "production")

    API_VERSIONING_ENABLED: bool = True
    API_DEFAULT_VERSION: str = "v1"
    API_SUPPORTED_VERSIONS: List[str] = ["v1", "v2"]

    class Config:
        case_sensitive = True


settings = Settings()