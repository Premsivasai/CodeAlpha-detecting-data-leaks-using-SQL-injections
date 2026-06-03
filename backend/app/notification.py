import logging
import asyncio
import json
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


async def persist_notification_attempt(app, notification_id: int, target: str | None, attempt_number: int, status: str, error_message: str | None = None, response_code: int | None = None, next_attempt_at: datetime | None = None):
    try:
        from app.database import AsyncSessionLocal
        from app.models import Notification, NotificationDeliveryAttempt

        async with AsyncSessionLocal() as db:
            attempt = NotificationDeliveryAttempt(
                notification_id=notification_id,
                target=target,
                attempt_number=attempt_number,
                status=status,
                error_message=error_message,
                response_code=response_code,
                next_attempt_at=next_attempt_at,
                delivered_at=datetime.utcnow() if status == 'delivered' else None,
            )
            db.add(attempt)

            note = await db.get(Notification, notification_id)
            if note:
                note.delivery_target = target
                note.delivery_attempts = attempt_number
                note.delivery_status = status
                note.last_delivery_error = error_message
                note.next_retry_at = next_attempt_at
                if status == 'delivered':
                    note.delivered_at = datetime.utcnow()
                await db.commit()
    except Exception as e:
        logger.warning(f"Failed to persist notification attempt: {e}")


async def process_notification_delivery_job(app, job: dict):
    import httpx
    notification_id = job.get('notification_id')
    target = job.get('target')
    payload = job.get('payload') or {}
    attempt_number = int(job.get('attempt_number', 1))
    max_attempts = int(job.get('max_attempts', 3))

    if not target:
        await persist_notification_attempt(app, notification_id, target, attempt_number, 'skipped')
        return

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.post(target, json=payload)
            if 200 <= response.status_code < 300:
                await persist_notification_attempt(app, notification_id, target, attempt_number, 'delivered', response_code=response.status_code)
                return

            raise RuntimeError(f"Webhook returned {response.status_code}")
    except Exception as exc:
        error_message = str(exc)
        next_delay = min(2 ** attempt_number, 60)
        next_attempt_at = datetime.utcnow() + timedelta(seconds=next_delay)
        await persist_notification_attempt(app, notification_id, target, attempt_number, 'failed', error_message=error_message, next_attempt_at=next_attempt_at)

        if attempt_number < max_attempts:
            async def retry_later():
                await asyncio.sleep(next_delay)
                retry_job = dict(job)
                retry_job['attempt_number'] = attempt_number + 1
                await app.state.notification_delivery_queue.put(retry_job)

            asyncio.create_task(retry_later())


async def notification_delivery_worker(app):
    while True:
        try:
            job = await app.state.notification_delivery_queue.get()
            await process_notification_delivery_job(app, job)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.warning(f"Notification delivery worker error: {e}")
            await asyncio.sleep(1)


async def enqueue_notification_delivery(app, notification_id: int, payload: dict, target: str | None = None, max_attempts: int = 3):
    queue = getattr(app.state, 'notification_delivery_queue', None)
    if queue is None:
        app.state.notification_delivery_queue = asyncio.Queue()
        queue = app.state.notification_delivery_queue

    job = {
        'notification_id': notification_id,
        'payload': payload,
        'target': target,
        'attempt_number': 1,
        'max_attempts': max_attempts,
    }
    await queue.put(job)
    return job
