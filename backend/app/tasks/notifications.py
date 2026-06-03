import httpx
from datetime import datetime
from celery import shared_task
import logging
import hmac
import hashlib
import json

logger = logging.getLogger(__name__)


def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    if not signature or not secret:
        return False
    
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)


class WebhookDispatcher:
    def __init__(self):
        self.webhooks = {}
    
    def register_webhook(self, name: str, url: str, secret: str = None, enabled: bool = True):
        self.webhooks[name] = {
            "url": url,
            "secret": secret,
            "enabled": enabled,
            "last_triggered": None,
            "failure_count": 0
        }
    
    def unregister_webhook(self, name: str) -> bool:
        if name in self.webhooks:
            del self.webhooks[name]
            return True
        return False
    
    async def send_webhook(self, name: str, event_type: str, data: dict) -> dict:
        if name not in self.webhooks:
            return {"success": False, "error": "Webhook not found"}
        
        webhook = self.webhooks[name]
        
        if not webhook["enabled"]:
            return {"success": False, "error": "Webhook disabled"}
        
        payload = {
            "event": event_type,
            "timestamp": datetime.utcnow().isoformat(),
            "data": data
        }
        
        payload_bytes = json.dumps(payload).encode()
        
        headers = {
            "Content-Type": "application/json",
            "X-Webhook-Event": event_type,
            "X-Webhook-Timestamp": payload["timestamp"]
        }
        
        if webhook["secret"]:
            signature = hmac.new(
                webhook["secret"].encode(),
                payload_bytes,
                hashlib.sha256
            ).hexdigest()
            headers["X-Webhook-Signature"] = f"sha256={signature}"
        
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    webhook["url"],
                    content=payload_bytes,
                    headers=headers
                )
                
                webhook["last_triggered"] = datetime.utcnow()
                
                if response.status_code >= 200 and response.status_code < 300:
                    webhook["failure_count"] = 0
                    return {"success": True, "status_code": response.status_code}
                else:
                    webhook["failure_count"] += 1
                    return {
                        "success": False,
                        "status_code": response.status_code,
                        "error": f"HTTP {response.status_code}"
                    }
                    
        except Exception as e:
            webhook["failure_count"] += 1
            logger.error(f"Webhook {name} failed: {e}")
            return {"success": False, "error": str(e)}
    
    def get_webhook_status(self, name: str) -> dict:
        if name not in self.webhooks:
            return None
        
        webhook = self.webhooks[name]
        return {
            "name": name,
            "url": webhook["url"],
            "enabled": webhook["enabled"],
            "last_triggered": webhook["last_triggered"].isoformat() if webhook["last_triggered"] else None,
            "failure_count": webhook["failure_count"]
        }
    
    def list_webhooks(self) -> list:
        return [self.get_webhook_status(name) for name in self.webhooks.keys()]


webhook_dispatcher = WebhookDispatcher()


@shared_task(bind=True, name="app.tasks.notifications.send_slack_alert")
def send_slack_alert(self, message: str, severity: str = "info", channel: str = None):
    import os
    
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    
    if not webhook_url:
        return {"success": False, "error": "Slack webhook not configured"}
    
    import asyncio
    
    async def _send():
        emoji = {
            "critical": ":rotating_light:",
            "high": ":warning:",
            "medium": ":large_orange_circle:",
            "low": ":information_source:"
        }.get(severity, ":speech_balloon:")
        
        payload = {
            "text": f"{emoji} *SecureShield Alert*",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"{emoji} Security Alert"}
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*{severity.upper()}*\n{message}"
                    }
                },
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": f"Timestamp: {datetime.utcnow().isoformat()}"}
                    ]
                }
            ]
        }
        
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(webhook_url, json=payload)
                return {"success": response.status_code == 200, "status": response.status_code}
        except Exception as e:
            logger.error(f"Slack notification failed: {e}")
            return {"success": False, "error": str(e)}
    
    import asyncio
    return asyncio.run(_send())


@shared_task(bind=True, name="app.tasks.notifications.send_webhook_notification")
def send_webhook_notification(self, webhook_name: str, event_type: str, data: dict):
    return asyncio.run(webhook_dispatcher.send_webhook(webhook_name, event_type, data))


@shared_task(bind=True, name="app.tasks.notifications.send_email_notification")
def send_email_notification(self, recipient: str, subject: str, body: str):
    import os
    
    smtp_host = os.getenv("SMTP_HOST")
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    
    if not all([smtp_host, smtp_user, smtp_password]):
        return {"success": False, "error": "SMTP not configured"}
    
    import asyncio
    
    async def _send():
        try:
            import aiosmtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            msg = MIMEMultipart()
            msg["From"] = smtp_user
            msg["To"] = recipient
            msg["Subject"] = subject
            
            msg.attach(MIMEText(body, "html"))
            
            await aiosmtplib.send(
                msg,
                hostname=smtp_host,
                port=587,
                username=smtp_user,
                password=smtp_password,
                tls=True
            )
            
            return {"success": True}
            
        except Exception as e:
            logger.error(f"Email notification failed: {e}")
            return {"success": False, "error": str(e)}
    
    return asyncio.run(_send())