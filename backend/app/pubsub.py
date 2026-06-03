import logging
import asyncio
import json
from datetime import datetime

logger = logging.getLogger(__name__)

active_websockets = []


def ensure_local_pubsub(app):
    queues = getattr(app.state, 'local_pubsub', None)
    if queues is None:
        queues = {
            'ws:attacks': asyncio.Queue(),
            'cache:security:invalidate': asyncio.Queue(),
        }
        app.state.local_pubsub = queues
    return queues


async def publish_app_event(app, channel: str, message):
    payload = json.dumps(message) if not isinstance(message, str) else message

    redis = getattr(app.state, 'redis', None)
    if redis is not None:
        try:
            await redis.publish(channel, payload)
            return True
        except Exception as exc:
            logger.warning(f"Redis publish failed for {channel}: {exc}")

    queues = ensure_local_pubsub(app)
    queue = queues.get(channel)
    if queue is not None:
        await queue.put(payload)
        return True

    return False


async def broadcast_attack(attack_data: dict):
    message = {
        "type": "attack",
        "data": attack_data,
        "timestamp": datetime.utcnow().isoformat()
    }

    disconnected = []
    for ws in active_websockets:
        try:
            await ws.send_json(message)
        except Exception:
            disconnected.append(ws)

    for ws in disconnected:
        if ws in active_websockets:
            active_websockets.remove(ws)
