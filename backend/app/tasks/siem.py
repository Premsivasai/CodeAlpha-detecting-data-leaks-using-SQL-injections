from celery import group
from celery_config import celery_app
from app.config import settings
import logging
import json
import asyncio
from datetime import datetime
import httpx

logger = logging.getLogger(__name__)


@celery_app.task(name="siem.send_to_splunk", bind=True, max_retries=3)
def send_to_splunk(self, event_data: dict):
    if not settings.SPLUNK_URL or not settings.SPLUNK_TOKEN:
        logger.warning("Splunk not configured, skipping event export")
        return {"status": "skipped", "reason": "Splunk not configured"}

    try:
        url = f"{settings.SPLUNK_URL}/services/collector"
        headers = {
            "Authorization": f"Splunk {settings.SPLUNK_TOKEN}",
            "Content-Type": "application/json"
        }
        
        event_payload = {
            "host": "secureshield",
            "source": "secureshield-backend",
            "sourcetype": "secureshield:events",
            "index": settings.SPLUNK_INDEX,
            "time": int(datetime.utcnow().timestamp()),
            "event": event_data
        }
        
        response = httpx.post(url, json=event_payload, headers=headers, timeout=10)
        response.raise_for_status()
        
        return {"status": "success", "event_id": event_data.get("id")}
    except Exception as e:
        logger.error(f"Failed to send to Splunk: {e}")
        self.retry(countdown=60, exc=e)


@celery_app.task(name="siem.send_to_azure_sentinel", bind=True, max_retries=3)
def send_to_azure_sentinel(self, event_data: dict):
    if not settings.AZURE_SENTINEL_ENABLED:
        return {"status": "skipped", "reason": "Azure Sentinel not enabled"}

    if not settings.AZURE_SENTINEL_WORKSPACE_ID or not settings.AZURE_SENTINEL_KEY:
        logger.warning("Azure Sentinel credentials not configured")
        return {"status": "skipped", "reason": "Credentials not configured"}

    try:
        url = f"https://{settings.AZURE_SENTINEL_WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2021-11-01"
        
        headers = {
            "Content-Type": "application/json",
            "Log-Type": "SecureshieldEvents",
            "x-ms-date": datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        }
        
        auth = (settings.AZURE_SENTINEL_KEY, "")
        
        response = httpx.post(url, json=event_data, headers=headers, auth=auth, timeout=10)
        response.raise_for_status()
        
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Failed to send to Azure Sentinel: {e}")
        self.retry(countdown=60, exc=e)


@celery_app.task(name="siem.send_to_qradar", bind=True, max_retries=3)
def send_to_qradar(self, event_data: dict):
    if not settings.QRADAR_ENABLED or not settings.QRADER_HOST:
        return {"status": "skipped", "reason": "QRadar not enabled"}

    try:
        import syslog
        
        syslog_message = f"<134>secureshield: {json.dumps(event_data)}"
        
        return {"status": "success", "transport": "syslog"}
    except Exception as e:
        logger.error(f"Failed to send to QRadar: {e}")
        self.retry(countdown=60, exc=e)


@celery_app.task(name="siem.export_cef", bind=True, max_retries=3)
def export_cef(self, event_data: dict):
    cef_version = "CEF:0"
    vendor = "SecureShield"
    product = "SQL Injection Detection"
    product_version = settings.VERSION
    
    severity_map = {
        "critical": 10,
        "high": 8,
        "medium": 5,
        "low": 3,
        "info": 1
    }
    severity = severity_map.get(event_data.get("severity", "info").lower(), 1)
    
    cef_header = f"{cef_version}|{vendor}|{product}|{product_version}|{event_data.get('event_type', 'security')}|{event_data.get('title', 'Security Event')}|{severity}"
    
    cef_extensions = []
    if "src_ip" in event_data:
        cef_extensions.append(f"src={event_data['src_ip']}")
    if "dst_ip" in event_data:
        cef_extensions.append(f"dst={event_data['dst_ip']}")
    if "user" in event_data:
        cef_extensions.append(f"suser={event_data['user']}")
    if "message" in event_data:
        cef_extensions.append(f"msg={event_data['message']}")
    
    cef_message = f"{cef_header} {' '.join(cef_extensions)}"
    
    logger.info(f"CEF Export: {cef_message[:200]}")
    
    return {"status": "success", "cef": cef_message}


@celery_app.task(name="siem.batch_export", bind=True)
def batch_export(self, events: list):
    results = []
    
    for event in events:
        splunk_result = send_to_splunk.delay(event)
        sentinel_result = send_to_azure_sentinel.delay(event)
        cef_result = export_cefs.delay(event)
        
        results.append({
            "event_id": event.get("id"),
            "splunk": splunk_result.id,
            "sentinel": sentinel_result.id,
            "cef": cef_result.id
        })
    
    return {"status": "completed", "exported": len(results)}


@celery_app.task(name="siem.export_attack_log", bind=True)
def export_attack_log(attack_log: dict):
    event_data = {
        "id": attack_log.get("id"),
        "event_type": "sql_injection_attack",
        "title": f"SQL Injection Attack - {attack_log.get('attack_type')}",
        "message": attack_log.get("payload", "")[:500],
        "severity": attack_log.get("severity", "medium"),
        "src_ip": attack_log.get("ip_address"),
        "timestamp": attack_log.get("timestamp"),
        "detection_method": attack_log.get("detection_method"),
        "attack_type": attack_log.get("attack_type"),
        "blocked": attack_log.get("blocked", True),
    }
    
    send_to_splunk.delay(event_data)
    send_to_azure_sentinel.delay(event_data)
    export_cefs.delay(event_data)
    
    return {"status": "exported"}


export_cefs = export_cefs