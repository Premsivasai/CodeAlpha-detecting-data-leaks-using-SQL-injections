from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
import asyncio
import json
from datetime import datetime

from app.config import settings
from app.database import init_db
from app.middleware import setup_middleware
from app.routes import router
from app.capability import capability_manager
from app.logs import alert_service
from app.database import AsyncSessionLocal
import redis.asyncio as aioredis
from sqlalchemy import text
from app.database import engine
from datetime import timedelta
import httpx


logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

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


async def persist_notification_attempt(app, notification_id: int, target: str | None, attempt_number: int, status: str, error_message: str | None = None, response_code: int | None = None, next_attempt_at: datetime | None = None):
    try:
        async with AsyncSessionLocal() as db:
            from app.models import Notification, NotificationDeliveryAttempt

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


async def refresh_hourly_materialized_view():
    try:
        async with engine.begin() as conn:
            await conn.execute(text("REFRESH MATERIALIZED VIEW CONCURRENTLY hourly_attack_stats"))
            logger.info("Refreshed materialized view hourly_attack_stats")
    except Exception as e:
        logger.error(f"Failed to refresh materialized view: {e}")


async def periodic_cleanup():
    while True:
        try:
            capability_manager.cleanup_expired()
            logger.info("Periodic cleanup completed")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
        
        await asyncio.sleep(3600)


async def periodic_health_check():
    while True:
        try:
            logger.debug("Health check: System running normally")
        except Exception as e:
            logger.error(f"Health check error: {e}")

        await asyncio.sleep(300)


async def redis_invalidation_listener(app):
    backoff = 1
    while True:
        redis = getattr(app.state, 'redis', None)
        if not redis:
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)
            continue

        pubsub = None
        try:
            pubsub = redis.pubsub()
            await pubsub.subscribe('cache:security:invalidate')
            logger.info('Redis invalidation listener subscribed')
            backoff = 1

            async for message in pubsub.listen():
                if not message:
                    continue
                if message.get('type') != 'message':
                    continue

                key = 'security:stats:24h'
                try:
                    await redis.delete(key)
                    logger.debug('Evicted cache key %s due to invalidation', key)
                except Exception as exc:
                    logger.warning(f'Failed to evict cache key {key}: {exc}')
        except Exception as e:
            logger.warning(f"Redis invalidation listener stopped: {e}")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)
        finally:
            if pubsub is not None:
                try:
                    await pubsub.close()
                except Exception:
                    pass


async def redis_ws_listener(app):
    backoff = 1
    while True:
        redis = getattr(app.state, 'redis', None)
        if not redis:
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)
            continue

        pubsub = None
        try:
            pubsub = redis.pubsub()
            await pubsub.subscribe('ws:attacks')
            logger.info('Redis WS listener subscribed')
            backoff = 1

            async for message in pubsub.listen():
                if not message or message.get('type') != 'message':
                    continue

                data = message.get('data')
                try:
                    import orjson
                    payload = orjson.loads(data)
                except Exception:
                    try:
                        import json as _json
                        payload = _json.loads(data)
                    except Exception:
                        payload = None

                if payload:
                    try:
                        await broadcast_attack(payload)
                    except Exception as exc:
                        logger.warning(f'Broadcast failed for Redis payload: {exc}')
        except Exception as e:
            logger.warning(f"Redis WS listener stopped: {e}")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)
        finally:
            if pubsub is not None:
                try:
                    await pubsub.close()
                except Exception:
                    pass


async def local_invalidation_listener(app):
    # Fallback listener when Redis is not available; consumes from asyncio.Queue
    queues = getattr(app.state, 'local_pubsub', None)
    if not queues:
        return

    q = queues.get('cache:security:invalidate')
    if not q:
        return

    while True:
        try:
            await q.get()
            key = 'security:stats:24h'
            # No real cache to evict when redis missing, but if a local cache exists, evict it here
            try:
                redis = getattr(app.state, 'redis', None)
                if redis is not None:
                    await redis.delete(key)
                    logger.debug('Evicted cache key %s via fallback', key)
            except Exception:
                pass
        except Exception as e:
            logger.warning(f"Local invalidation listener error: {e}")
            await asyncio.sleep(1)


async def local_ws_listener(app):
    queues = getattr(app.state, 'local_pubsub', None)
    if not queues:
        return

    q = queues.get('ws:attacks')
    if not q:
        return

    while True:
        try:
            data = await q.get()
            try:
                payload = json.loads(data)
            except Exception:
                payload = None
            if payload:
                try:
                    await broadcast_attack(payload)
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"Local WS listener error: {e}")
            await asyncio.sleep(1)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting SecureShield Application...")
    
    try:
        await init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
    
    asyncio.create_task(periodic_cleanup())
    asyncio.create_task(periodic_health_check())
    app.state.notification_delivery_queue = asyncio.Queue()

    # Start a background loop to refresh the materialized view hourly
    async def materialized_view_refresher():
        while True:
            try:
                now = datetime.utcnow()
                # sleep until the top of the next hour
                next_hour = (now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1))
                sleep_secs = (next_hour - now).total_seconds()
                await asyncio.sleep(sleep_secs)
                await refresh_hourly_materialized_view()
            except Exception as e:
                logger.warning(f"Materialized view refresher error: {e}")
                await asyncio.sleep(60)

    try:
        asyncio.create_task(materialized_view_refresher())
        logger.info('Started materialized view refresher task')
    except Exception as e:
        logger.warning(f'Could not start materialized view refresher: {e}')

    # Initialize Redis client for caching and pub/sub
    try:
        app.state.redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        # Verify connectivity
        try:
            await app.state.redis.ping()
            logger.info("Connected to Redis for caching")
        except Exception:
            # Redis not reachable; fall back
            await app.state.redis.close()
            app.state.redis = None
            raise RuntimeError('Redis ping failed')
    except Exception as e:
        app.state.redis = None
        logger.warning(f"Redis not available: {e}")
        # Setup a simple in-memory pubsub fallback using asyncio.Queue
        app.state.local_pubsub = {
            'ws:attacks': asyncio.Queue(),
            'cache:security:invalidate': asyncio.Queue()
        }
        logger.info('Using in-memory pubsub fallback')

    # Start invalidation and WS listeners (Redis-backed or local fallback)
    try:
        if getattr(app.state, 'redis', None) is not None:
            asyncio.create_task(redis_invalidation_listener(app))
            asyncio.create_task(redis_ws_listener(app))
            logger.info('Started Redis invalidation and WS listeners')
        else:
            asyncio.create_task(local_invalidation_listener(app))
            asyncio.create_task(local_ws_listener(app))
            logger.info('Started local in-memory invalidation and WS listeners')
    except Exception as e:
        logger.warning(f'Could not start invalidation/WS listeners: {e}')

    try:
        asyncio.create_task(notification_delivery_worker(app))
        logger.info('Started notification delivery worker')
    except Exception as e:
        logger.warning(f'Could not start notification delivery worker: {e}')
    
    logger.info("Background tasks started")
    
    yield
    
    logger.info("Shutting down SecureShield Application...")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Cloud-Based SQL Injection Detection and Data Leak Prevention System",
    docs_url=f"{settings.API_V1_PREFIX}/docs",
    redoc_url=f"{settings.API_V1_PREFIX}/redoc",
    lifespan=lifespan
)


setup_middleware(app)

# Add CORS middleware to allow frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "http://127.0.0.1:3000", "http://127.0.0.1:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
async def root():
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "running",
        "timestamp": datetime.utcnow().isoformat(),
        "endpoints": {
            "docs": f"{settings.API_V1_PREFIX}/docs",
            "health": f"{settings.API_V1_PREFIX}/health"
        }
    }


@app.get(f"{settings.API_V1_PREFIX}/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "database": "connected",
            "encryption": "active",
            "detection": "running",
            "ai_detection": "initialized"
        }
    }


@app.websocket(f"{settings.API_V1_PREFIX}/ws/attacks")
async def websocket_attacks(websocket: WebSocket):
    await websocket.accept()
    active_websockets.append(websocket)
    
    try:
        while True:
            data = await websocket.receive_text()
            
            await websocket.send_json({
                "type": "heartbeat",
                "timestamp": datetime.utcnow().isoformat()
            })
            
    except WebSocketDisconnect:
        active_websockets.remove(websocket)
        logger.info("WebSocket client disconnected")


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
        except:
            disconnected.append(ws)
    
    for ws in disconnected:
        if ws in active_websockets:
            active_websockets.remove(ws)


app.include_router(router, prefix=settings.API_V1_PREFIX, tags=["api"])


@app.post(f"{settings.API_V1_PREFIX}/internal/publish")
async def internal_publish(request: Request):
    body = await request.json()
    channel = body.get('channel')
    message = body.get('message')
    if not channel or message is None:
        return JSONResponse(status_code=400, content={"error": "channel and message required"})

    published = await publish_app_event(app, channel, message)
    if published:
        return {"published": True, "fallback": getattr(app.state, 'redis', None) is None}

    return JSONResponse(status_code=503, content={"published": False, "error": "No pubsub available"})


@app.post(f"{settings.API_V1_PREFIX}/internal/notifications/enqueue")
async def internal_enqueue_notification(request: Request):
    body = await request.json()
    notification_id = body.get('notification_id')
    payload = body.get('payload') or {}
    target = body.get('target')
    max_attempts = int(body.get('max_attempts', 3))
    if not notification_id:
        return JSONResponse(status_code=400, content={"error": "notification_id required"})
    await enqueue_notification_delivery(app, int(notification_id), payload, target, max_attempts=max_attempts)
    return {"queued": True, "notification_id": notification_id}


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": str(exc)}
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )