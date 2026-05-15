from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from typing import Callable
import time
import logging
from app.config import settings
from app.logs import ip_blocker
from app.database import AsyncSessionLocal


logger = logging.getLogger(__name__)


class IPBlockingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        
        async with AsyncSessionLocal() as db:
            is_blocked = await ip_blocker.is_blocked(db, client_ip)
            
            if is_blocked:
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": "Your IP has been blocked due to security concerns",
                        "error": "ip_blocked"
                    }
                )
        
        response = await call_next(request)
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, calls: int = 60, period: int = 60):
        super().__init__(app)
        self.calls = calls
        self.period = period
        self.clients = {}
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        current_time = time.time()
        
        if client_ip not in self.clients:
            self.clients[client_ip] = []
        
        self.clients[client_ip] = [
            ts for ts in self.clients[client_ip]
            if current_time - ts < self.period
        ]
        
        if len(self.clients[client_ip]) >= self.calls:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many requests. Please try again later.",
                    "error": "rate_limit_exceeded"
                }
            )
        
        self.clients[client_ip].append(current_time)
        
        response = await call_next(request)
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
        
        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()
        
        client_ip = request.client.host if request.client else "unknown"
        method = request.method
        path = request.url.path
        
        try:
            response = await call_next(request)
            
            process_time = time.time() - start_time
            
            logger.info(
                f"{method} {path} - {response.status_code} - {process_time:.3f}s - {client_ip}"
            )
            
            response.headers["X-Process-Time"] = str(process_time)
            
            return response
        except Exception as e:
            logger.error(f"Request error: {str(e)} - {method} {path} - {client_ip}")
            raise


def setup_middleware(app):
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    
    app.add_middleware(SecurityHeadersMiddleware)
    
    app.add_middleware(RateLimitMiddleware, calls=settings.RATE_LIMIT_PER_MINUTE, period=60)
    
    app.add_middleware(IPBlockingMiddleware)
    
    app.add_middleware(RequestLoggingMiddleware)

    # Keep CORS as the outermost middleware so all responses include CORS headers,
    # including early returns from rate limit / IP block middleware.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
