from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from typing import Callable, Optional
import time
import uuid
import logging
from app.config import settings
from app.logs import ip_blocker
from app.database import AsyncSessionLocal
from app.models import User


logger = logging.getLogger(__name__)

ROLE_RATE_LIMITS = {
    'user': 60,
    'moderator': 120,
    'security_analyst': 180,
    'admin': 300,
    'super_admin': 1000
}

REQUEST_SIZE_LIMIT = 10 * 1024 * 1024


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


class RoleBasedRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, default_calls: int = 60, period: int = 60):
        super().__init__(app)
        self.default_calls = default_calls
        self.period = period
        self.clients = {}
    
    def _get_rate_limit(self, user_role: Optional[str]) -> int:
        if user_role:
            return ROLE_RATE_LIMITS.get(user_role, self.default_calls)
        return self.default_calls
    
    def _get_client_key(self, client_ip: str, user_id: Optional[int]) -> str:
        if user_id:
            return f"user:{user_id}"
        return f"ip:{client_ip}"
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        current_time = time.time()
        
        user_role = None
        user_id = None
        
        if hasattr(request.state, "user") and request.state.user:
            user = request.state.user
            user_role = user.role.value if hasattr(user.role, 'value') else str(user.role)
            user_id = user.id
        
        rate_limit = self._get_rate_limit(user_role)
        client_key = self._get_client_key(client_ip, user_id)
        
        redis = getattr(request.app.state, 'redis', None)
        
        if redis is not None:
            try:
                key = f"rate:{client_key}"
                count = await redis.incr(key)
                if count == 1:
                    await redis.expire(key, self.period)
                if int(count) > rate_limit:
                    return JSONResponse(
                        status_code=429,
                        content={
                            "detail": f"Rate limit exceeded. Limit: {rate_limit} requests per minute",
                            "error": "rate_limit_exceeded",
                            "retry_after": self.period
                        },
                        headers={"Retry-After": str(self.period)}
                    )
            except Exception:
                pass
        
        if client_key not in self.clients:
            self.clients[client_key] = []
        
        self.clients[client_key] = [
            ts for ts in self.clients[client_key]
            if current_time - ts < self.period
        ]
        
        if len(self.clients[client_key]) >= rate_limit:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": f"Rate limit exceeded. Limit: {rate_limit} requests per minute",
                    "error": "rate_limit_exceeded",
                    "retry_after": self.period
                },
                headers={"Retry-After": str(self.period)}
            )
        
        self.clients[client_key].append(current_time)
        
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
        response.headers["X-Request-ID"] = str(uuid.uuid4())
        
        return response


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        
        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_size: int = REQUEST_SIZE_LIMIT):
        super().__init__(app)
        self.max_size = max_size
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        content_length = request.headers.get("content-length")
        
        if content_length and int(content_length) > self.max_size:
            return JSONResponse(
                status_code=413,
                content={
                    "detail": f"Request too large. Maximum size: {self.max_size} bytes",
                    "error": "payload_too_large"
                }
            )
        
        response = await call_next(request)
        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()
        
        client_ip = request.client.host if request.client else "unknown"
        method = request.method
        path = request.url.path
        request_id = getattr(request.state, 'request_id', 'unknown')
        
        try:
            response = await call_next(request)
            
            process_time = time.time() - start_time
            
            logger.info(
                f"[{request_id}] {method} {path} - {response.status_code} - {process_time:.3f}s - {client_ip}"
            )
            
            response.headers["X-Process-Time"] = str(process_time)
            
            return response
        except Exception as e:
            logger.error(f"[{request_id}] Request error: {str(e)} - {method} {path} - {client_ip}")
            raise


class TenantIsolationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        tenant_id = request.headers.get("X-Tenant-ID")
        tenant_slug = request.headers.get("X-Tenant-Slug")
        tenant_domain = request.headers.get("X-Tenant-Domain")

        resolved_tenant_id = None
        if tenant_id:
            try:
                resolved_tenant_id = int(tenant_id)
            except (TypeError, ValueError):
                resolved_tenant_id = None

        request.state.tenant_id = resolved_tenant_id
        request.state.tenant_slug = tenant_slug
        request.state.tenant_context = {
            "tenant_id": resolved_tenant_id,
            "tenant_slug": tenant_slug,
            "tenant_domain": tenant_domain,
            "tenant_key_prefix": f"tenant:{resolved_tenant_id}" if resolved_tenant_id is not None else None,
        }

        response = await call_next(request)
        return response


def setup_middleware(app):
    app.add_middleware(GZipMiddleware, minimum_size=1000)

    app.add_middleware(SecurityHeadersMiddleware)

    app.add_middleware(RequestIDMiddleware)

    app.add_middleware(RequestSizeLimitMiddleware)

    app.add_middleware(RoleBasedRateLimitMiddleware, default_calls=settings.RATE_LIMIT_PER_MINUTE, period=60)

    app.add_middleware(TenantIsolationMiddleware)

    app.add_middleware(IPBlockingMiddleware)

    app.add_middleware(RequestLoggingMiddleware)
