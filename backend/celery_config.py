from celery import Celery
from celery.schedules import crontab
import os

CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/"))
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", os.getenv("REDIS_URL", "redis://localhost:6379/1"))

celery_app = Celery(
    "secureshield",
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
    include=[
        "app.tasks.reports",
        "app.tasks.security",
        "app.tasks.cleanup",
        "app.tasks.notifications",
        "app.tasks.ai_inference",
        "app.tasks.siem",
        "app.tasks.billing"
    ]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,
    task_soft_time_limit=3000,
    worker_prefetch_multiplier=4,
    worker_max_tasks_per_child=1000,
    result_expires=86400,
    task_routes={
        "app.tasks.reports.*": {"queue": "reports"},
        "app.tasks.security.*": {"queue": "security"},
        "app.tasks.cleanup.*": {"queue": "cleanup"},
        "app.tasks.notifications.*": {"queue": "notifications"},
        "app.tasks.ai_inference.*": {"queue": "ai-inference"},
        "app.tasks.siem.*": {"queue": "siem"},
        "app.tasks.billing.*": {"queue": "billing"},
    },
    beat_schedule={
        "cleanup-expired-tokens": {
            "task": "app.tasks.cleanup.cleanup_expired_tokens",
            "schedule": crontab(minute="*/30"),
        },
        "cleanup-expired-sessions": {
            "task": "app.tasks.cleanup.cleanup_expired_sessions",
            "schedule": crontab(hour="*/1"),
        },
        "generate-daily-report": {
            "task": "app.tasks.reports.generate_daily_report",
            "schedule": crontab(hour=1, minute=0),
        },
        "sync-threat-intel": {
            "task": "app.tasks.security.sync_threat_intel",
            "schedule": crontab(hour="*/6"),
        },
        "cleanup-old-logs": {
            "task": "app.tasks.cleanup.cleanup_old_logs",
            "schedule": crontab(hour=2, minute=0),
        },
        "update-security-metrics": {
            "task": "app.tasks.security.update_security_metrics",
            "schedule": crontab(minute="*/5"),
        },
        "sync-tenant-usage": {
            "task": "app.tasks.billing.sync_tenant_usage",
            "schedule": crontab(hour="*/1"),
        },
    },
    task_annotations={
        "app.tasks.ai_inference.*": {"rate_limit": "10/m"},
        "app.tasks.security.sync_threat_intel": {"rate_limit": "1/m"},
    }
)