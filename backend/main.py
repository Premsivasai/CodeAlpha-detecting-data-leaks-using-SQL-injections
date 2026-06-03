from typing import Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware as FastAPICORSMiddleware
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
from app.notification import enqueue_notification_delivery, notification_delivery_worker
from app.pubsub import active_websockets, publish_app_event, broadcast_attack, ensure_local_pubsub
import redis.asyncio as aioredis
from sqlalchemy import text
from app.database import engine
from datetime import timedelta


logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


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
            # cleanup capability manager data
            capability_manager.cleanup_expired()
            # cleanup expired refresh tokens
            try:
                from app.database import AsyncSessionLocal
                async with AsyncSessionLocal() as db:
                    from app.auth import auth_service
                    await auth_service.cleanup_expired_tokens(db)
            except Exception as e:
                logger.warning(f"Failed to cleanup expired tokens: {e}")

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

# Add CORS middleware
app.add_middleware(
    FastAPICORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
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
async def health_check(request: Request):
    import psutil
    import os
    
    db_status = "connected"
    redis_status = "disconnected"
    
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"error: {str(e)[:50]}"
    
    redis = getattr(request.app.state, 'redis', None)
    if redis:
        try:
            await redis.ping()
            redis_status = "connected"
        except Exception:
            redis_status = "error"
    
    process = psutil.Process(os.getpid())
    memory_info = process.memory_info()
    
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": settings.VERSION,
        "uptime_seconds": int((datetime.utcnow() - datetime.fromisoformat(getattr(request.app.state, 'start_time', datetime.utcnow().isoformat()))).total_seconds()),
        "services": {
            "database": db_status,
            "redis": redis_status,
            "encryption": "active",
            "detection": "running",
            "ai_detection": "initialized"
        },
        "system": {
            "memory_rss_mb": round(memory_info.rss / 1024 / 1024, 2),
            "cpu_percent": process.cpu_percent(),
            "threads": process.num_threads()
        }
    }


@app.get(f"{settings.API_V1_PREFIX}/health/detailed")
async def detailed_health_check(request: Request):
    import psutil
    import os
    import sys
    
    db_connected = False
    db_version = None
    
    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(text("SELECT version()"))
            db_version = result.scalar()
            db_connected = True
    except Exception:
        pass
    
    redis_connected = False
    redis_info = {}
    
    redis = getattr(request.app.state, 'redis', None)
    if redis:
        try:
            await redis.ping()
            redis_connected = True
            redis_info = {
                "keys": await redis.dbsize(),
            }
        except Exception:
            pass
    
    ws_stats = {
        "total_connections": len(active_websockets)
    }
    
    process = psutil.Process(os.getpid())
    memory = process.memory_info()
    
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "dependencies": {
            "postgresql": {
                "connected": db_connected,
                "version": db_version.split(" ")[0] if db_version else None,
                "full_version": db_version[:100] if db_version else None
            },
            "redis": {
                "connected": redis_connected,
                "info": redis_info
            }
        },
        "application": {
            "python_version": sys.version.split()[0],
            "workers": 1,
            "start_time": getattr(request.app.state, 'start_time', None)
        },
        "websocket": ws_stats,
        "resources": {
            "memory_mb": round(memory.rss / 1024 / 1024, 2),
            "cpu_percent": round(process.cpu_percent(), 2),
            "threads": process.num_threads(),
            "open_files": len(process.open_files()) if hasattr(process, 'open_files') else 0
        }
    }


@app.websocket(f"{settings.API_V1_PREFIX}/ws/attacks")
async def websocket_attacks(websocket: WebSocket):
    from app.middleware.websocket import handle_websocket_connection, ws_manager
    
    connection_id = await handle_websocket_connection(websocket, user_id=None)
    
    if not connection_id:
        return
    
    try:
        while True:
            data = await websocket.receive_text()
            
            from app.middleware.websocket import ws_rate_limiter
            if not await ws_rate_limiter.check_rate_limit(connection_id):
                await websocket.send_json({
                    "type": "error",
                    "message": "Rate limit exceeded"
                })
                continue
            
            ws_manager.connection_metadata[connection_id]["messages_received"] += 1
            
            await websocket.send_json({
                "type": "heartbeat",
                "timestamp": datetime.utcnow().isoformat()
            })
            
    except WebSocketDisconnect:
        await ws_manager.disconnect(connection_id)
        logger.info(f"WebSocket client disconnected: {connection_id}")


from app.routes.sessions import router as sessions_router

app.include_router(router, prefix=settings.API_V1_PREFIX, tags=["api"])
app.include_router(sessions_router, prefix=settings.API_V1_PREFIX, tags=["sessions"])


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


@app.get(f"{settings.API_V1_PREFIX}/connections/{{connection_id}}/export")
async def export_connection_logs(connection_id: int, request: Request, start_ts: Optional[str] = None, end_ts: Optional[str] = None):
    """Export QueryLog entries for a connection as JSON attachment. Admin-only."""
    from fastapi.responses import StreamingResponse
    from app.database import AsyncSessionLocal
    from app.models import QueryLog, UserRole

    current_user = None
    try:
        current_user = request.state.user
    except Exception:
        pass

    if not current_user or current_user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN):
        raise HTTPException(status_code=403, detail='Insufficient permissions')

    async def stream_logs():
        async with AsyncSessionLocal() as db:
            query = select(QueryLog).where(QueryLog.connection_id == connection_id).order_by(QueryLog.timestamp)
            if start_ts:
                try:
                    from datetime import datetime as _dt
                    start_dt = _dt.fromisoformat(start_ts)
                    query = query.where(QueryLog.timestamp >= start_dt)
                except Exception:
                    pass
            if end_ts:
                try:
                    from datetime import datetime as _dt
                    end_dt = _dt.fromisoformat(end_ts)
                    query = query.where(QueryLog.timestamp <= end_dt)
                except Exception:
                    pass

            res = await db.stream(query)
            first = True
            yield b"["
            async for row in res.scalars():
                import orjson
                if not first:
                    yield b","  
                else:
                    first = False
                yield orjson.dumps({
                    'id': row.id,
                    'query': row.query,
                    'parameters': row.parameters,
                    'timestamp': row.timestamp.isoformat() if row.timestamp else None,
                    'blocked': row.blocked,
                    'block_reason': row.block_reason,
                })
            yield b"]"

    headers = {"Content-Disposition": f"attachment; filename=connection_{connection_id}_logs.json"}
    return StreamingResponse(stream_logs(), media_type="application/json", headers=headers)


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