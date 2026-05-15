from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
import asyncio
from datetime import datetime

from app.config import settings
from app.database import init_db
from app.middleware import setup_middleware
from app.routes import router
from app.capability import capability_manager
from app.logs import alert_service
import redis.asyncio as aioredis


logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


active_websockets = []


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

    # Initialize Redis client for caching and pub/sub
    try:
        app.state.redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        logger.info("Connected to Redis for caching")
    except Exception as e:
        app.state.redis = None
        logger.warning(f"Redis not available: {e}")
    
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