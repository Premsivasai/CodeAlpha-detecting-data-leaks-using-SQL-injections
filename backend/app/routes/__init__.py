from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from datetime import datetime
from typing import Optional, List
from copy import deepcopy
from pydantic import BaseModel, EmailStr, Field
from app.database import get_db
from app.models import User, UserRole, AttackLog, SystemAlert, SecurityMetric, BlockedIP, AIDetectionResult
from app.models import GlobalConfig, DatabaseConnection, QueryLog
from app.auth import auth_service, get_current_user, get_password_hash
from app.config import settings
import pyotp
from app.capability import capability_manager, permission_checker
from app.detection import sql_injection_detector, Severity
from app.ai_detection import ai_detector
from app.logs import log_service, alert_service, ip_blocker, secure_execution_service
from app.encryption import encryption_service
from app.security.query_sandbox import query_sandbox
from app.db_connectors.postgres_connector import PostgresConnector
from app.db_connectors import MySQLConnector, MongoDBConnector
from app.db_connectors.pool_manager import db_pool_manager
from app.utils.rate_limiter import allow_request
import asyncio
import socket
try:
    import redis.asyncio as aioredis
except Exception:
    aioredis = None
import logging
import json

logger = logging.getLogger(__name__)


router = APIRouter()

# Simple in-memory fallback for rate limiting when Redis isn't available
RATE_LIMIT_STORE = {}


class ReplayRequest(BaseModel):
    query_log_id: int
    allow_reexecute: bool = False


async def _check_rate_limit(http_request: Request, current_user: User) -> None:
    """Enforce per-user/tenant rate limits using Redis when available, else fallback to in-memory."""
    # Determine limits by role
    try:
        role_name = current_user.role.name.lower() if hasattr(current_user.role, 'name') else str(current_user.role).lower()
    except Exception:
        role_name = 'user'

    limits = {
        'super_admin': 1000,
        'admin': 500,
        'security_analyst': 300,
        'user': 60,
    }
    window_seconds = 60
    limit = limits.get(role_name, limits['user'])

    redis = getattr(http_request.app.state, 'redis', None)
    key = f"rate:{current_user.tenant_id or 'global'}:{current_user.id}"

    if redis is not None:
        try:
            allowed = await allow_request(redis, key, limit, window_seconds)
            if not allowed:
                raise HTTPException(status_code=429, detail='Rate limit exceeded')
            return
        except HTTPException:
            raise
        except Exception:
            # Fallthrough to in-memory fallback
            pass

    # In-memory sliding window (coarse)
    now_ts = int(datetime.utcnow().timestamp())
    entry = RATE_LIMIT_STORE.get(key)
    if not entry or entry['expires_at'] <= now_ts:
        RATE_LIMIT_STORE[key] = {'count': 1, 'expires_at': now_ts + window_seconds}
    else:
        entry['count'] += 1
        if entry['count'] > limit:
            raise HTTPException(status_code=429, detail='Rate limit exceeded')



class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    phone_number: Optional[str] = None
    role: str = "user"


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    phone_number: Optional[str] = None
    role: str
    is_active: bool
    is_verified: bool
    last_login: Optional[datetime] = None
    created_at: datetime


class UserSettingsModel(BaseModel):
    general: dict = Field(default_factory=dict)
    security: dict = Field(default_factory=dict)
    notifications: dict = Field(default_factory=dict)
    detection: dict = Field(default_factory=dict)
    database: dict = Field(default_factory=dict)


DEFAULT_USER_SETTINGS = {
    "general": {
        "autoRefresh": True,
        "refreshInterval": 30,
        "language": "en",
    },
    "security": {
        "mfaEnabled": False,
        "sessionTimeout": 30,
        "ipWhitelist": False,
        "allowedIPs": [],
        "apiKeyRequired": True,
    },
    "notifications": {
        "emailAlerts": True,
        "slackWebhook": "",
        "webhookUrl": "",
        "alertOnCritical": True,
        "alertOnHigh": True,
        "alertOnMedium": False,
        "alertOnLow": False,
    },
    "detection": {
        "aiDetectionEnabled": True,
        "threatScoreThreshold": 0.7,
        "autoBlockEnabled": True,
        "logAllQueries": False,
        "maxQueryLength": 5000,
    },
    "database": {
        "postgresHost": "localhost",
        "postgresPort": 5432,
        "postgresDatabase": "secureshield",
        "redisHost": "localhost",
        "redisPort": 6379,
    },
}


def _merge_user_settings(stored_settings: Optional[dict]) -> dict:
    merged = deepcopy(DEFAULT_USER_SETTINGS)

    if not isinstance(stored_settings, dict):
        return merged

    for category, default_values in merged.items():
        incoming_values = stored_settings.get(category, {})
        if isinstance(incoming_values, dict):
            default_values.update(incoming_values)

    return merged


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    user: dict


class LoginRequest(BaseModel):
    username: str
    password: str


class CapabilityRequest(BaseModel):
    permissions: List[str]
    resources: List[str]
    expiration_days: int = 7


class CapabilityResponse(BaseModel):
    token: str
    permissions: List[str]
    resources: List[str]
    expires_at: str


class AttackDetectionRequest(BaseModel):
    query: str
    user_id: Optional[int] = None
    target: str = "database"


class AttackDetectionResponse(BaseModel):
    is_malicious: bool
    attack_type: Optional[str]
    severity: str
    confidence: float
    details: str
    detection_method: str
    threat_score: Optional[float] = None
    risk_level: Optional[str] = None
    explanation: Optional[str] = None
    sandbox_blocked: Optional[bool] = None
    affected_tables: Optional[List[str]] = None
    recommended_action: Optional[str] = None


class AIDetectionResponse(BaseModel):
    threat_score: float
    prediction: str
    confidence: float


class BlockIPRequest(BaseModel):
    ip_address: str
    reason: str = None
    is_permanent: bool = False


class AlertResponse(BaseModel):
    id: int
    alert_type: str
    severity: str
    title: str
    message: str
    is_resolved: bool
    metadata: Optional[dict] = None
    created_at: datetime


class SecurityStatsResponse(BaseModel):
    total_attacks_blocked: int
    attacks_today: int
    active_blocked_ips: int
    active_alerts: int
    ai_predictions_today: int
    top_attack_types: List[dict]
    timeseries: List[dict]


class IPBlockResponse(BaseModel):
    ip_address: str
    blocked: bool
    reason: Optional[str]


class TestConnectionRequest(BaseModel):
    type: str  # 'db' or 'redis'
    host: str
    port: int
    database: Optional[str] = None


class TestConnectionResponse(BaseModel):
    ok: bool
    details: Optional[str] = None


class AdminConfigItem(BaseModel):
    key: str
    value: dict
    encrypted: bool = False


class DatabaseConnectionCreate(BaseModel):
    name: str
    db_type: str = Field(pattern=r"^(postgres|mysql|mongodb)$")
    host: str
    port: int
    database_name: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    ssl_enabled: bool = True
    metadata: Optional[dict] = None


class DatabaseConnectionResponse(BaseModel):
    id: int
    tenant_id: Optional[int] = None
    name: str
    db_type: str
    host: str
    port: int
    database_name: Optional[str] = None
    username: Optional[str] = None
    ssl_enabled: bool
    is_active: bool
    status: str
    last_tested_at: Optional[datetime] = None
    last_test_ok: Optional[bool] = None
    metadata: Optional[dict] = None
    created_at: datetime
    updated_at: datetime


class DatabaseConnectionTestRequest(BaseModel):
    host: Optional[str] = None
    port: Optional[int] = None
    db_type: Optional[str] = Field(default=None, pattern=r"^(postgres|mysql|mongodb)$")
    database_name: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    ssl_enabled: bool = True
    connection_id: Optional[int] = None


class SecureQueryRequest(BaseModel):
    query: str
    parameters: Optional[List] = None
    fetch_one: bool = False
    fetch_all: bool = True
    # For non-SQL backends (mongodb) specify mode and collection
    mode: Optional[str] = None
    collection: Optional[str] = None


@router.post("/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate, db: AsyncSession = Depends(get_db)):
    try:
        role = UserRole[user_data.role.upper()]
    except KeyError:
        role = UserRole.USER
    
    user = await auth_service.register_user(
        db,
        user_data.username,
        user_data.email,
        user_data.password,
        user_data.phone_number,
        role
    )
    
    await log_service.log_audit(
        db,
        user_id=user.id,
        tenant_id=user.tenant_id,
        action="user_registered",
        resource="users",
        details={"username": user.username, "role": role.value}
    )
    
    try:
        decrypted_email = encryption_service.decrypt(user.email)
    except:
        decrypted_email = user.email
    
    return UserResponse(
        id=user.id,
        username=user.username,
        email=decrypted_email,
        phone_number=user.phone_number,
        role=user.role.value,
        is_active=user.is_active,
        is_verified=user.is_verified,
        last_login=user.last_login,
        created_at=user.created_at
    )


@router.post("/auth/login", response_model=TokenResponse)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
):
    user = await auth_service.authenticate_user(db, form_data.username, form_data.password)
    
    if not user:
        await log_service.log_failed_login(
            db,
            form_data.username,
            "unknown"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    await log_service.log_audit(
        db,
        user_id=user.id,
        tenant_id=user.tenant_id,
        action="user_login",
        resource="auth",
        details={"username": user.username}
    )

    tokens = auth_service.create_tokens(user)

    # Persist refresh token for revocation support
    try:
        from app.models import RefreshToken
        from datetime import timedelta
        import hashlib

        expires_at = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        token_hash = hashlib.sha256(tokens['refresh_token'].encode('utf-8')).hexdigest()
        rt = RefreshToken(token=token_hash, user_id=user.id, expires_at=expires_at)
        db.add(rt)
        await db.commit()
    except Exception:
        # If persisting fails, continue but log a warning
        logger.warning('Failed to persist refresh token to DB')

    return tokens


class RefreshTokenRequest(BaseModel):
    refresh_token: str


@router.post("/auth/refresh", response_model=TokenResponse)
async def refresh_token(
    request: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db)
):
    from app.auth import decode_token, create_access_token, create_refresh_token
    
    try:
        payload = decode_token(request.refresh_token)

        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )

        # Ensure refresh token exists in DB and is not revoked (tokens are stored hashed)
        try:
            import hashlib
            from app.models import RefreshToken as RT
            token_hash = hashlib.sha256(request.refresh_token.encode('utf-8')).hexdigest()
            result_rt = await db.execute(select(RT).where(RT.token == token_hash))
            rt_obj = result_rt.scalar_one_or_none()
            if not rt_obj or rt_obj.revoked:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token revoked or not found")
        except HTTPException:
            raise
        except Exception:
            # If DB check fails, reject the token for safety
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )

        try:
            user_id = int(user_id)
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )
        
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        
        if user is None or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        access_token = create_access_token(data={"sub": user.id, "role": user.role.value})
        refresh_token_new = create_refresh_token(data={"sub": user.id})

        # Rotate refresh token: revoke old and persist new hashed token
        try:
            import hashlib
            from datetime import timedelta
            from app.models import RefreshToken as RT

            # revoke old
            rt_obj.revoked = True
            db.add(rt_obj)

            # persist new
            new_hash = hashlib.sha256(refresh_token_new.encode('utf-8')).hexdigest()
            expires_at = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
            new_rt = RT(token=new_hash, user_id=user.id, expires_at=expires_at)
            db.add(new_rt)
            await db.commit()
        except Exception:
            # best-effort: if DB rotation fails, continue returning tokens
            try:
                await db.rollback()
            except Exception:
                pass

        return {
            "access_token": access_token,
            "refresh_token": refresh_token_new,
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "username": user.username,
                "role": user.role.value
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )


@router.post('/auth/mfa/setup')
async def mfa_setup(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    # generate TOTP secret and store on user (disabled until verified)
    secret = pyotp.random_base32()
    current_user.mfa_secret = secret
    current_user.mfa_enabled = False
    db.add(current_user)
    await db.commit()

    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=current_user.email, issuer_name=settings.PROJECT_NAME)

    return {"provisioning_uri": provisioning_uri, "secret": secret}


class MFAVerifyRequest(BaseModel):
    token: str


@router.post('/auth/mfa/verify')
async def mfa_verify(request: MFAVerifyRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if not current_user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA not initialized for user")

    totp = pyotp.TOTP(current_user.mfa_secret)
    if totp.verify(request.token, valid_window=1):
        current_user.mfa_enabled = True
        db.add(current_user)
        await db.commit()
        return {"status": "mfa_enabled"}
    else:
        raise HTTPException(status_code=400, detail="Invalid token")


@router.post('/admin/config/test', response_model=TestConnectionResponse)
async def test_connection(request: TestConnectionRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    # admin-only
    if current_user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN):
        raise HTTPException(status_code=403, detail='Insufficient permissions')

    host = request.host
    port = request.port
    t = 3
    try:
        # quick TCP check
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=t)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    except Exception as e:
        return TestConnectionResponse(ok=False, details=f"TCP connect failed: {str(e)}")

    if request.type == 'redis' and aioredis:
        try:
            r = aioredis.Redis(host=host, port=port, db=0)
            pong = await asyncio.wait_for(r.ping(), timeout=t)
            await r.close()
            if pong:
                return TestConnectionResponse(ok=True, details='Redis PONG')
            else:
                return TestConnectionResponse(ok=False, details='Redis ping failed')
        except Exception as e:
            return TestConnectionResponse(ok=False, details=f"Redis test failed: {str(e)}")

    # For DB we only check TCP reachability above; a more thorough check would require credentials
    return TestConnectionResponse(ok=True, details='TCP reachable')


@router.post('/connections', response_model=DatabaseConnectionResponse)
async def create_database_connection(
    payload: DatabaseConnectionCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if current_user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN, UserRole.SECURITY_ANALYST):
        raise HTTPException(status_code=403, detail='Insufficient permissions')

    encrypted_password = encryption_service.encrypt(payload.password) if payload.password else None
    connection = await secure_execution_service.register_connection(db, current_user.tenant_id, payload, encrypted_password)

    await log_service.log_audit(
        db,
        user_id=current_user.id,
        tenant_id=current_user.tenant_id,
        action='database_connection_created',
        resource='database_connections',
        details={'connection_id': connection.id, 'db_type': payload.db_type, 'name': payload.name}
    )

    return DatabaseConnectionResponse(
        id=connection.id,
        tenant_id=connection.tenant_id,
        name=connection.name,
        db_type=connection.db_type,
        host=connection.host,
        port=connection.port,
        database_name=connection.database_name,
        username=connection.username,
        ssl_enabled=connection.ssl_enabled,
        is_active=connection.is_active,
        status=connection.status,
        last_tested_at=connection.last_tested_at,
        last_test_ok=connection.last_test_ok,
        metadata=connection.connection_metadata or {},
        created_at=connection.created_at,
        updated_at=connection.updated_at,
    )


@router.get('/connections', response_model=List[DatabaseConnectionResponse])
async def list_database_connections(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if current_user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN, UserRole.SECURITY_ANALYST):
        raise HTTPException(status_code=403, detail='Insufficient permissions')

    connections = await secure_execution_service.list_connections(db, current_user.tenant_id)
    return [
        DatabaseConnectionResponse(
            id=connection.id,
            tenant_id=connection.tenant_id,
            name=connection.name,
            db_type=connection.db_type,
            host=connection.host,
            port=connection.port,
            database_name=connection.database_name,
            username=connection.username,
            ssl_enabled=connection.ssl_enabled,
            is_active=connection.is_active,
            status=connection.status,
            last_tested_at=connection.last_tested_at,
            last_test_ok=connection.last_test_ok,
            metadata=connection.connection_metadata or {},
            created_at=connection.created_at,
            updated_at=connection.updated_at,
        )
        for connection in connections
    ]


@router.post('/connections/test', response_model=TestConnectionResponse)
async def test_database_connection(
    request: DatabaseConnectionTestRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if current_user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN, UserRole.SECURITY_ANALYST):
        raise HTTPException(status_code=403, detail='Insufficient permissions')

    connection = None
    if request.connection_id is not None:
        connection = await secure_execution_service.get_connection(db, request.connection_id, current_user.tenant_id)
        if connection is None:
            raise HTTPException(status_code=404, detail='Connection not found')

    db_type = (request.db_type or (connection.db_type if connection else '')).lower()
    host = request.host or (connection.host if connection else None)
    port = request.port or (connection.port if connection else None)
    database_name = request.database_name or (connection.database_name if connection else None)
    username = request.username or (connection.username if connection else None)
    password = request.password or None
    ssl_enabled = request.ssl_enabled if request.connection_id is None else bool(connection.ssl_enabled)

    if not host or not port:
        raise HTTPException(status_code=400, detail='Host and port are required')

    ok = False
    details = 'Connection test not performed'

    if db_type == 'postgres':
        connector = PostgresConnector(host=host, port=port, user=username or 'postgres', password=password or '', database=database_name or 'postgres', ssl_enabled=ssl_enabled)
        ok = await connector.test_connection()
        details = 'PostgreSQL reachable' if ok else 'PostgreSQL connection failed'
    elif db_type == 'mysql':
        connector = MySQLConnector(host=host, port=port, user=username or 'root', password=password or '', database=database_name or '', ssl_enabled=ssl_enabled)
        ok = await connector.test_connection()
        details = 'MySQL reachable' if ok else 'MySQL connection failed'
    elif db_type == 'mongodb':
        connector = MongoDBConnector(host=host, port=port, user=username or '', password=password or '', database=database_name or 'admin', tls_enabled=ssl_enabled)
        ok = await connector.connect()
        if ok:
            ok = await connector.test_connection()
        details = 'MongoDB reachable' if ok else 'MongoDB connection failed'
    else:
        raise HTTPException(status_code=400, detail='Unsupported database type')

    if connection is not None:
        await secure_execution_service.update_test_status(db, connection, ok, 'healthy' if ok else 'failed')

    return TestConnectionResponse(ok=ok, details=details)


@router.get('/connections/{connection_id}/schema')
async def get_connection_schema(
    connection_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if current_user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN, UserRole.SECURITY_ANALYST):
        raise HTTPException(status_code=403, detail='Insufficient permissions')

    connection = await secure_execution_service.get_connection(db, connection_id, current_user.tenant_id)
    if connection is None:
        raise HTTPException(status_code=404, detail='Connection not found')

    if connection.db_type == 'postgres':
        connector = PostgresConnector(host=connection.host, port=connection.port, user=connection.username or 'postgres', password=encryption_service.decrypt(connection.password_encrypted) if connection.password_encrypted else '', database=connection.database_name or 'postgres', ssl_enabled=connection.ssl_enabled)
        tables = await connector.execute_query(
            """
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
            ORDER BY table_name
            """,
            fetch_all=True,
        )
        schema = []
        for row in tables or []:
            table_name = row.get('table_name') if hasattr(row, 'get') else row['table_name'] if isinstance(row, dict) else row[0]
            columns = await connector.execute_query(
                """
                SELECT column_name, data_type
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = $1
                ORDER BY ordinal_position
                """,
                params=[table_name],
                fetch_all=True,
            )
            schema.append({
                'table': table_name,
                'columns': [dict(column) if hasattr(column, 'items') else column for column in (columns or [])],
            })
        return {'connection_id': connection_id, 'db_type': connection.db_type, 'schema': schema}

    if connection.db_type == 'mysql':
        connector = MySQLConnector(host=connection.host, port=connection.port, user=connection.username or 'root', password=encryption_service.decrypt(connection.password_encrypted) if connection.password_encrypted else '', database=connection.database_name or '', ssl_enabled=connection.ssl_enabled)
        tables = await connector.execute_query("SHOW TABLES", fetch_all=True)
        schema = []
        for row in tables or []:
            table_name = list(row.values())[0] if isinstance(row, dict) else row[0]
            columns = await connector.execute_query(f"SHOW COLUMNS FROM `{table_name}`", fetch_all=True)
            schema.append({
                'table': table_name,
                'columns': [dict(column) if hasattr(column, 'items') else column for column in (columns or [])],
            })
        return {'connection_id': connection_id, 'db_type': connection.db_type, 'schema': schema}

    return {'connection_id': connection_id, 'db_type': connection.db_type, 'schema': connection.connection_metadata or {}}


@router.get('/connections/{connection_id}/history')
async def get_connection_history(
    connection_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if current_user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN, UserRole.SECURITY_ANALYST):
        raise HTTPException(status_code=403, detail='Insufficient permissions')

    connection = await secure_execution_service.get_connection(db, connection_id, current_user.tenant_id)
    if connection is None:
        raise HTTPException(status_code=404, detail='Connection not found')

    result = await db.execute(
        select(QueryLog)
        .where(QueryLog.connection_id == connection_id)
        .order_by(desc(QueryLog.timestamp))
        .limit(50)
    )
    rows = result.scalars().all()
    return [
        {
            'id': row.id,
            'query': row.query,
            'parameters': row.parameters or {},
            'execution_time': row.execution_time,
            'blocked': row.blocked,
            'block_reason': row.block_reason,
            'timestamp': row.timestamp.isoformat() if row.timestamp else None,
        }
        for row in rows
    ]


@router.post('/connections/{connection_id}/execute')
async def execute_secure_query(
    connection_id: int,
    payload: SecureQueryRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    http_request: Request = None,
):
    if current_user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN, UserRole.SECURITY_ANALYST):
        raise HTTPException(status_code=403, detail='Insufficient permissions')

    connection = await secure_execution_service.get_connection(db, connection_id, current_user.tenant_id)
    if connection is None:
        raise HTTPException(status_code=404, detail='Connection not found')

    # enforce basic rate limiting per-user/tenant
    try:
        await _check_rate_limit(http_request, current_user)
    except HTTPException:
        await log_service.log_audit(
            db,
            user_id=current_user.id,
            tenant_id=current_user.tenant_id,
            action='rate_limited',
            resource='database_connections',
            details={'connection_id': connection_id}
        )
        raise

    sandbox = query_sandbox.analyze(payload.query)
    if sandbox.blocked:
        await log_service.log_query(
            db,
            user_id=current_user.id,
            query=payload.query,
            parameters={"connection_id": connection_id, "reason": sandbox.explanation},
            execution_time=0.0,
            ip_address=None,
            blocked=True,
            block_reason=sandbox.recommendation,
            tenant_id=current_user.tenant_id,
            connection_id=connection_id,
        )
        raise HTTPException(status_code=403, detail=sandbox.recommendation)

    if connection.db_type == 'postgres':
        connector = db_pool_manager.register_postgres(
            name=connection.name,
            host=connection.host,
            port=connection.port,
            user=connection.username or 'postgres',
            password=encryption_service.decrypt(connection.password_encrypted) if connection.password_encrypted else '',
            database=connection.database_name or 'postgres',
            ssl=connection.ssl_enabled,
            tenant_id=current_user.tenant_id or 'global',
        )
    elif connection.db_type == 'mysql':
        connector = db_pool_manager.register_mysql(
            name=connection.name,
            host=connection.host,
            port=connection.port,
            user=connection.username or 'root',
            password=encryption_service.decrypt(connection.password_encrypted) if connection.password_encrypted else '',
            database=connection.database_name or '',
            ssl=connection.ssl_enabled,
            tenant_id=current_user.tenant_id or 'global',
        )
    elif connection.db_type == 'mongodb':
        connector = db_pool_manager.register_mongodb(
            name=connection.name,
            host=connection.host,
            port=connection.port,
            user=connection.username or '',
            password=encryption_service.decrypt(connection.password_encrypted) if connection.password_encrypted else '',
            database=connection.database_name or 'admin',
            tls=connection.ssl_enabled,
            tenant_id=current_user.tenant_id or 'global',
        )
    else:
        raise HTTPException(status_code=400, detail='Unsupported database type')

    query_start = datetime.utcnow()

    # MongoDB uses different execution primitives
    # set role-based execution timeout
    try:
        role_name = current_user.role.name.lower() if hasattr(current_user.role, 'name') else str(current_user.role).lower()
    except Exception:
        role_name = 'user'
    timeout_map = {
        'super_admin': 60,
        'admin': 60,
        'security_analyst': 30,
        'user': 10,
    }
    exec_timeout = timeout_map.get(role_name, 10)

    if connection.db_type == 'mongodb':
        # require collection for Mongo operations
        if not payload.collection:
            raise HTTPException(status_code=400, detail='MongoDB execution requires a collection name')

        # try to interpret query as JSON for find/aggregate
        doc_payload = payload.query
        try:
            if isinstance(payload.query, str):
                doc_payload = json.loads(payload.query)
        except Exception:
            doc_payload = payload.query

        if payload.mode and str(payload.mode).lower().startswith('agg'):
            pipeline = doc_payload if isinstance(doc_payload, list) else [doc_payload]
            result = await asyncio.wait_for(connector.execute_aggregate(payload.collection, pipeline), timeout=exec_timeout)
        else:
            query_doc = doc_payload if isinstance(doc_payload, dict) else {}
            result = await asyncio.wait_for(connector.execute_find(payload.collection, query_doc, projection=None, limit=200), timeout=exec_timeout)
    else:
        result = await asyncio.wait_for(connector.execute_query(
            payload.query,
            params=payload.parameters,
            fetch_one=payload.fetch_one,
            fetch_all=payload.fetch_all,
        ), timeout=exec_timeout)
    execution_time = (datetime.utcnow() - query_start).total_seconds()

    await log_service.log_query(
        db,
        user_id=current_user.id,
        query=payload.query,
        parameters={"connection_id": connection_id, "params": payload.parameters or []},
        execution_time=execution_time,
        ip_address=None,
        blocked=False,
        block_reason=None,
        tenant_id=current_user.tenant_id,
        connection_id=connection_id,
    )

    result_rows = []
    if isinstance(result, list):
        for row in result[:200]:
            if hasattr(row, 'items'):
                result_rows.append(dict(row))
            else:
                result_rows.append(row)
    elif hasattr(result, 'items'):
        result_rows = [dict(result)]
    elif result is None:
        result_rows = []
    else:
        result_rows = [result]

    await log_service.log_audit(
        db,
        user_id=current_user.id,
        tenant_id=current_user.tenant_id,
        action='secure_query_executed',
        resource='database_connections',
        details={'connection_id': connection_id, 'rows': len(result_rows), 'blocked': False},
    )

    return {
        'connection': {
            'id': connection.id,
            'name': connection.name,
            'db_type': connection.db_type,
        },
        'analysis': sandbox.to_dict(),
        'execution_time': execution_time,
        'row_count': len(result_rows),
        'results': result_rows,
    }



@router.post('/connections/{connection_id}/replay')
async def replay_query(
    connection_id: int,
    replay: ReplayRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    http_request: Request = None,
):
    # fetch the logged query
    stmt = select(QueryLog).where(QueryLog.id == replay.query_log_id, QueryLog.connection_id == connection_id)
    res = await db.execute(stmt)
    qlog = res.scalar_one_or_none()
    if qlog is None:
        raise HTTPException(status_code=404, detail='Query log entry not found')

    # sandbox the original query
    sandbox_result = query_sandbox.analyze(qlog.query)

    # record that a replay was requested (simulation or real)
    await log_service.log_audit(
        db,
        user_id=current_user.id,
        tenant_id=current_user.tenant_id,
        action='replay_requested',
        resource='database_connections',
        details={'connection_id': connection_id, 'query_log_id': qlog.id, 'simulated': not replay.allow_reexecute}
    )

    response_base = {
        'query_log_id': qlog.id,
        'original_query': qlog.query,
        'parameters': qlog.parameters,
        'sandbox': sandbox_result.to_dict(),
        'simulated': True,
    }

    if not replay.allow_reexecute:
        return response_base

    # only admins/super-admins may re-execute
    if current_user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN):
        raise HTTPException(status_code=403, detail='Insufficient permissions to re-execute')

    # proceed with actual execution (admin opted in)
    connection = await secure_execution_service.get_connection(db, connection_id, current_user.tenant_id)
    if connection is None:
        raise HTTPException(status_code=404, detail='Connection not found')

    if connection.db_type == 'postgres':
        connector = db_pool_manager.register_postgres(
            name=connection.name,
            host=connection.host,
            port=connection.port,
            user=connection.username or 'postgres',
            password=encryption_service.decrypt(connection.password_encrypted) if connection.password_encrypted else '',
            database=connection.database_name or 'postgres',
            ssl=connection.ssl_enabled,
            tenant_id=current_user.tenant_id or 'global',
        )
    elif connection.db_type == 'mysql':
        connector = db_pool_manager.register_mysql(
            name=connection.name,
            host=connection.host,
            port=connection.port,
            user=connection.username or 'root',
            password=encryption_service.decrypt(connection.password_encrypted) if connection.password_encrypted else '',
            database=connection.database_name or '',
            ssl=connection.ssl_enabled,
            tenant_id=current_user.tenant_id or 'global',
        )
    elif connection.db_type == 'mongodb':
        connector = db_pool_manager.register_mongodb(
            name=connection.name,
            host=connection.host,
            port=connection.port,
            user=connection.username or '',
            password=encryption_service.decrypt(connection.password_encrypted) if connection.password_encrypted else '',
            database=connection.database_name or 'admin',
            tls=connection.ssl_enabled,
            tenant_id=current_user.tenant_id or 'global',
        )
    else:
        raise HTTPException(status_code=400, detail='Unsupported database type')

    # determine timeout by role
    try:
        role_name = current_user.role.name.lower() if hasattr(current_user.role, 'name') else str(current_user.role).lower()
    except Exception:
        role_name = 'user'
    timeout_map = {
        'super_admin': 60,
        'admin': 60,
        'security_analyst': 30,
        'user': 10,
    }
    exec_timeout = timeout_map.get(role_name, 10)

    # perform execution
    query_start = datetime.utcnow()
    try:
        if connection.db_type == 'mongodb':
            payload = qlog.query
            # try to interpret as JSON
            try:
                if isinstance(payload, str):
                    payload_obj = json.loads(payload)
                else:
                    payload_obj = payload
            except Exception:
                payload_obj = payload

            if isinstance(payload_obj, list):
                        # run explain-like safe aggregate: limit results and prefer read on secondary
                        safe_pipeline = payload_obj if isinstance(payload_obj, list) else [payload_obj]
                        # ensure a safe limit exists
                        if not any('$limit' in str(stage) for stage in safe_pipeline):
                            safe_pipeline = safe_pipeline + [{'$limit': 100}]
                        result = await asyncio.wait_for(connector.execute_aggregate(qlog.collection or '', safe_pipeline), timeout=exec_timeout)
            else:
                query_doc = payload_obj if isinstance(payload_obj, dict) else {}
                result = await asyncio.wait_for(connector.execute_find(qlog.collection or '', query_doc, projection=None, limit=200), timeout=exec_timeout)
        else:
            params = qlog.parameters or {}
            result = await asyncio.wait_for(connector.execute_query(qlog.query, params=params, fetch_one=False, fetch_all=True), timeout=exec_timeout)

        execution_time = (datetime.utcnow() - query_start).total_seconds()

        # log the re-execution
        await log_service.log_query(
            db,
            user_id=current_user.id,
            query=qlog.query,
            parameters={'connection_id': connection_id, 'params': qlog.parameters or {}},
            execution_time=execution_time,
            ip_address=None,
            blocked=False,
            block_reason=None,
            tenant_id=current_user.tenant_id,
            connection_id=connection_id,
        )

        await log_service.log_audit(
            db,
            user_id=current_user.id,
            tenant_id=current_user.tenant_id,
            action='replay_executed',
            resource='database_connections',
            details={'connection_id': connection_id, 'query_log_id': qlog.id, 'rows': len(result) if isinstance(result, list) else 1}
        )

        return {'simulated': False, 'execution_time': execution_time, 'rows': len(result) if isinstance(result, list) else 1, 'results': result}

    except asyncio.TimeoutError:
        await log_service.log_audit(
            db,
            user_id=current_user.id,
            tenant_id=current_user.tenant_id,
            action='replay_timeout',
            resource='database_connections',
            details={'connection_id': connection_id, 'query_log_id': qlog.id}
        )
        raise HTTPException(status_code=504, detail='Replay execution timed out')
    except Exception as e:
        await log_service.log_audit(
            db,
            user_id=current_user.id,
            tenant_id=current_user.tenant_id,
            action='replay_failed',
            resource='database_connections',
            details={'connection_id': connection_id, 'query_log_id': qlog.id, 'error': str(e)}
        )
        raise HTTPException(status_code=500, detail='Replay execution failed')


@router.get('/admin/config')
async def get_admin_config(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if current_user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN):
        raise HTTPException(status_code=403, detail='Insufficient permissions')

    result = await db.execute(select(GlobalConfig))
    rows = result.scalars().all()
    out = {}
    for r in rows:
        try:
            val = r.value
            if r.encrypted:
                # decrypt string fields if stored as string
                if isinstance(val, str):
                    try:
                        val = encryption_service.decrypt(val)
                    except Exception:
                        pass
            out[r.key] = {"value": val, "encrypted": r.encrypted, "version": r.version, "updated_at": r.updated_at}
        except Exception:
            out[r.key] = {"value": r.value, "encrypted": r.encrypted}
    return out


@router.put('/admin/config')
async def put_admin_config(items: List[AdminConfigItem], current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if current_user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN):
        raise HTTPException(status_code=403, detail='Insufficient permissions')

    from app.models import GlobalConfig as GC

    updated = []
    for item in items:
        stmt = select(GC).where(GC.key == item.key)
        res = await db.execute(stmt)
        obj = res.scalar_one_or_none()
        value_to_store = item.value
        if item.encrypted:
            # encrypt JSON as string
            try:
                value_to_store = encryption_service.encrypt(item.value)
            except Exception:
                value_to_store = item.value

        if obj:
            obj.value = value_to_store
            obj.encrypted = item.encrypted
            obj.version = (obj.version or 1) + 1
            obj.updated_by = current_user.id
            db.add(obj)
            updated.append(item.key)
        else:
            new = GC(key=item.key, value=value_to_store, encrypted=item.encrypted, updated_by=current_user.id)
            db.add(new)
            updated.append(item.key)

    try:
        await db.commit()
    except Exception:
        try:
            await db.rollback()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail='Failed to persist config')

    await log_service.log_audit(db, user_id=current_user.id, action='update_global_config', resource='global_config', details={'keys': updated})

    return {"updated": updated}


@router.post('/auth/logout')
async def logout(refresh_token: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        import hashlib
        from app.models import RefreshToken as RT
        token_hash = hashlib.sha256(refresh_token.encode('utf-8')).hexdigest()
        result_rt = await db.execute(select(RT).where(RT.token == token_hash, RT.user_id == current_user.id))
        rt_obj = result_rt.scalar_one_or_none()
        if rt_obj:
            rt_obj.revoked = True
            db.add(rt_obj)
            await db.commit()
            return {"status": "revoked"}
        else:
            raise HTTPException(status_code=404, detail="Refresh token not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to revoke token")


@router.get("/users/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    try:
        decrypted_email = encryption_service.decrypt(current_user.email)
    except:
        decrypted_email = current_user.email
    
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=decrypted_email,
        phone_number=current_user.phone_number,
        role=current_user.role.value,
        is_active=current_user.is_active,
        is_verified=current_user.is_verified,
        last_login=current_user.last_login,
        created_at=current_user.created_at
    )


@router.get("/users/me/settings", response_model=UserSettingsModel)
async def get_current_user_settings(current_user: User = Depends(get_current_user)):
    return _merge_user_settings(current_user.settings)


@router.put("/users/me/settings", response_model=UserSettingsModel)
async def update_current_user_settings(
    payload: UserSettingsModel,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    merged = _merge_user_settings(payload.model_dump())
    current_user.settings = merged
    await db.commit()
    await db.refresh(current_user)
    return merged


@router.get("/users", response_model=List[UserResponse])
async def list_users(
    skip: int = 0,
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not permission_checker.has_permission(
        permission_checker.get_permissions(current_user.role.value),
        "users:read"
    ):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    result = await db.execute(
        select(User).offset(skip).limit(limit)
    )
    users = result.scalars().all()
    
    return [
        UserResponse(
            id=u.id,
            username=u.username,
            email="***encrypted***",
                phone_number=u.phone_number,
            role=u.role.value,
            is_active=u.is_active,
            is_verified=u.is_verified,
            last_login=u.last_login,
            created_at=u.created_at
        )
        for u in users
    ]


@router.post("/capability/generate", response_model=CapabilityResponse)
async def generate_capability(
    request: CapabilityRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    token = capability_manager.generate_capability(
        user_id=current_user.id,
        username=current_user.username,
        permissions=request.permissions,
        resources=request.resources,
        expiration_days=request.expiration_days
    )
    
    capabilities = capability_manager.get_user_capabilities(current_user.id)
    latest = capabilities[-1] if capabilities else None
    
    await log_service.log_audit(
        db,
        user_id=current_user.id,
        action="capability_generated",
        resource="capabilities",
        details={"permissions": request.permissions, "resources": request.resources}
    )
    
    return CapabilityResponse(
        token=token,
        permissions=request.permissions,
        resources=request.resources,
        expires_at=latest['expires_at'] if latest else datetime.utcnow().isoformat()
    )


@router.get("/capability/list")
async def list_capabilities(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    capabilities = capability_manager.get_user_capabilities(current_user.id)
    return {"capabilities": capabilities}


@router.post("/detection/analyze", response_model=AttackDetectionResponse)
async def analyze_query(
    request: AttackDetectionRequest,
    db: AsyncSession = Depends(get_db)
):
    sandbox_result = query_sandbox.analyze(request.query)
    result = sql_injection_detector.detect(request.query)
    
    if result.is_malicious:
        await log_service.log_attack(
            db,
            user_id=request.user_id,
            ip_address="unknown",
            attack_type=result.attack_type.value if result.attack_type else "unknown",
            payload=request.query,
            target=request.target,
            severity=result.severity.value,
            detection_method=result.detection_method,
            blocked=True
        )
        
        if result.severity in [Severity.CRITICAL, Severity.HIGH]:
            await alert_service.create_alert(
                db,
                alert_type="sql_injection",
                severity=result.severity.value,
                title=f"SQL Injection Attempt - {result.attack_type.value if result.attack_type else 'Unknown'}",
                message=f"Attack detected on {request.target}",
                metadata={"payload": request.query[:500], "confidence": result.confidence}
            )
    
    return AttackDetectionResponse(
        is_malicious=result.is_malicious,
        attack_type=result.attack_type.value if result.attack_type else None,
        severity=result.severity.value,
        confidence=result.confidence,
        details=result.details,
        detection_method=result.detection_method,
        threat_score=sandbox_result.threat_score,
        risk_level=sandbox_result.risk_level,
        explanation=sandbox_result.explanation,
        sandbox_blocked=sandbox_result.blocked,
        affected_tables=sandbox_result.affected_tables,
        recommended_action=sandbox_result.recommendation,
    )


@router.post("/detection/ai-analyze", response_model=AIDetectionResponse)
async def ai_analyze_query(
    query: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = ai_detector.predict(query)
    
    ai_result = AIDetectionResult(
        query=query,
        threat_score=result.threat_score,
        prediction=result.prediction,
        confidence=result.confidence,
        model_version="1.0.0",
        features=result.features
    )
    db.add(ai_result)
    await db.commit()
    
    if result.threat_score > 0.7:
        await log_service.log_attack(
            db,
            user_id=current_user.id,
            ip_address="unknown",
            attack_type="ai_detected",
            payload=query,
            target="database",
            severity="high",
            detection_method="ai_ml",
            blocked=True,
            metadata={"threat_score": result.threat_score, "confidence": result.confidence}
        )
    
    return AIDetectionResponse(
        threat_score=result.threat_score,
        prediction=result.prediction,
        confidence=result.confidence
    )


@router.get("/logs/attacks", response_model=List[dict])
async def get_attack_logs(
    skip: int = 0,
    limit: int = 50,
    attack_type: Optional[str] = None,
    severity: Optional[str] = None,
    query: Optional[str] = None,
    blocked: Optional[bool] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not permission_checker.has_permission(
        permission_checker.get_permissions(current_user.role.value),
        "logs:read"
    ):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    logs = await log_service.get_attack_logs(
        db, limit, skip, attack_type, severity, blocked, query, start_time, end_time
    )
    
    return [
        {
            "id": log.id,
            "attack_type": log.attack_type,
            "severity": log.severity,
            "payload": log.payload[:200] + "..." if len(log.payload) > 200 else log.payload,
            "blocked": log.blocked,
            "detection_method": log.detection_method,
            "timestamp": log.timestamp.isoformat(),
            "ip_address": log.ip_address
        }
        for log in logs
    ]


@router.get("/security/stats", response_model=SecurityStatsResponse)
async def get_security_stats(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not permission_checker.has_permission(
        permission_checker.get_permissions(current_user.role.value),
        "analytics:read"
    ):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    from datetime import timedelta
    
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    # Try to serve from Redis cache if available (short TTL)
    redis = getattr(request.app.state, 'redis', None)
    cache_key = "security:stats:24h"
    if redis is not None:
        try:
            cached = await redis.get(cache_key)
            if cached:
                import orjson
                return orjson.loads(cached)
        except Exception:
            # ignore cache errors
            redis = None
    
    total_attacks = await db.execute(
        select(func.count(AttackLog.id))
    )
    total_attacks_blocked = total_attacks.scalar() or 0
    
    attacks_today = await db.execute(
        select(func.count(AttackLog.id)).where(AttackLog.timestamp >= today_start)
    )
    attacks_today_count = attacks_today.scalar() or 0
    
    blocked_ips = await db.execute(select(func.count(BlockedIP.id)))
    active_blocked_ips = blocked_ips.scalar() or 0
    
    active_alerts = await db.execute(
        select(func.count(SystemAlert.id)).where(SystemAlert.is_resolved == False)
    )
    active_alerts_count = active_alerts.scalar() or 0
    
    ai_predictions = await db.execute(
        select(func.count(AIDetectionResult.id)).where(AIDetectionResult.timestamp >= today_start)
    )
    ai_predictions_count = ai_predictions.scalar() or 0
    
    attack_types_result = await db.execute(
        select(AttackLog.attack_type, func.count(AttackLog.id))
        .group_by(AttackLog.attack_type)
        .order_by(desc(func.count(AttackLog.id)))
        .limit(5)
    )
    top_attack_types = [
        {"type": row[0], "count": row[1]}
        for row in attack_types_result.all()
    ]
    # Build a 24-hour hourly timeseries for the dashboard
    from sqlalchemy import cast, TIMESTAMP, text
    hours_back = 24
    series_query = (
        select(func.date_trunc('hour', AttackLog.timestamp).label('hour'), func.count(AttackLog.id))
        .where(AttackLog.timestamp >= datetime.utcnow() - timedelta(hours=hours_back))
        .group_by(text('hour'))
        .order_by(text('hour'))
    )
    series_result = await db.execute(series_query)
    series_rows = series_result.all()
    timeseries = []
    # Build a map for quick lookup
    series_map = { r[0].replace(minute=0, second=0, microsecond=0).isoformat(): r[1] for r in series_rows }
    for i in range(hours_back):
        hour_dt = (datetime.utcnow().replace(minute=0, second=0, microsecond=0) - timedelta(hours=(hours_back - 1 - i)))
        key = hour_dt.isoformat()
        timeseries.append({"time": hour_dt.isoformat(), "attacks": series_map.get(key, 0)})

    # Cache result in Redis for a short period.
    try:
        redis = getattr(request.app.state, 'redis', None)
        if redis is not None:
            import orjson

            payload = {
                "total_attacks_blocked": total_attacks_blocked,
                "attacks_today": attacks_today_count,
                "active_blocked_ips": active_blocked_ips,
                "active_alerts": active_alerts_count,
                "ai_predictions_today": ai_predictions_count,
                "top_attack_types": top_attack_types,
                "timeseries": timeseries,
            }
            await redis.set(cache_key, orjson.dumps(payload), ex=15)
    except Exception:
        pass
    
    return SecurityStatsResponse(
        total_attacks_blocked=total_attacks_blocked,
        attacks_today=attacks_today_count,
        active_blocked_ips=active_blocked_ips,
        active_alerts=active_alerts_count,
        ai_predictions_today=ai_predictions_count,
        top_attack_types=top_attack_types
        ,
        timeseries=timeseries
    )


@router.get("/alerts", response_model=List[AlertResponse])
async def get_alerts(
    resolved: bool = False,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not permission_checker.has_permission(
        permission_checker.get_permissions(current_user.role.value),
        "alerts:read"
    ):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    if resolved:
        result = await db.execute(
            select(SystemAlert).order_by(desc(SystemAlert.created_at)).limit(50)
        )
    else:
        result = await alert_service.get_active_alerts(db)
    
    return [
        AlertResponse(
            id=alert.id,
            alert_type=alert.alert_type,
            severity=alert.severity,
            title=alert.title,
            message=alert.message,
            is_resolved=alert.is_resolved,
            metadata=alert.meta,
            created_at=alert.created_at
        )
        for alert in result
    ]


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not permission_checker.has_permission(
        permission_checker.get_permissions(current_user.role.value),
        "alerts:write"
    ):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    alert = await alert_service.resolve_alert(db, alert_id)
    
    await log_service.log_audit(
        db,
        user_id=current_user.id,
        action="alert_resolved",
        resource="alerts",
        details={"alert_id": alert_id}
    )
    
    return {"status": "resolved", "alert_id": alert_id}


@router.post("/ip/block", response_model=IPBlockResponse)
async def block_ip(
    request: BlockIPRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not permission_checker.has_permission(
        permission_checker.get_permissions(current_user.role.value),
        "security:write"
    ):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    blocked = await ip_blocker.block_ip(
        db,
        request.ip_address,
        request.reason,
        request.is_permanent
    )
    
    await log_service.log_audit(
        db,
        user_id=current_user.id,
        action="ip_blocked",
        resource="security",
        details={"ip": request.ip_address, "reason": request.reason}
    )
    
    return IPBlockResponse(
        ip_address=request.ip_address,
        blocked=True,
        reason=request.reason
    )


@router.post("/ip/unblock")
async def unblock_ip(
    ip_address: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not permission_checker.has_permission(
        permission_checker.get_permissions(current_user.role.value),
        "security:write"
    ):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    success = await ip_blocker.unblock_ip(db, ip_address)
    
    return {"ip_address": ip_address, "unblocked": success}


@router.get("/ip/blocked")
async def list_blocked_ips(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not permission_checker.has_permission(
        permission_checker.get_permissions(current_user.role.value),
        "security:read"
    ):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    result = await db.execute(select(BlockedIP))
    ips = result.scalars().all()
    
    return [
        {
            "ip_address": ip.ip_address,
            "reason": ip.reason,
            "blocked_at": ip.blocked_at.isoformat(),
            "is_permanent": ip.is_permanent,
            "expires_at": ip.expires_at.isoformat() if ip.expires_at else None
        }
        for ip in ips
    ]

 

# --- Incident response and notifications (lightweight implementations) ---


class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    metadata: Optional[dict] = None


class IncidentResponse(BaseModel):
    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    metadata: Optional[dict]
    created_at: datetime


class IncidentAttackSummary(BaseModel):
    id: int
    attack_type: str
    severity: str
    detection_method: str
    ip_address: str
    timestamp: datetime
    payload: Optional[str] = None


class IncidentDetailResponse(IncidentResponse):
    fingerprint: Optional[str] = None
    event_count: int = 0
    risk_score: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    related_attack_types: List[str] = Field(default_factory=list)
    related_ips: List[str] = Field(default_factory=list)
    attacks: List[IncidentAttackSummary] = Field(default_factory=list)


class IncidentResolveRequest(BaseModel):
    resolution_note: Optional[str] = None


@router.post("/incidents", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    incident: IncidentCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    from app.models import Incident as IncidentModel

    new_incident = IncidentModel(
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        status="open",
        meta=incident.metadata or {},
        created_by=current_user.id
    )

    db.add(new_incident)
    await db.commit()
    await db.refresh(new_incident)

    await log_service.log_audit(
        db,
        user_id=current_user.id,
        action="incident_created",
        resource="incidents",
        details={"incident_id": new_incident.id, "title": new_incident.title}
    )

    # Create a system alert for the incident so it's visible in alerts UI
    try:
        await alert_service.create_alert(
            db,
            alert_type="incident",
            severity=incident.severity,
            title=f"Incident: {incident.title}",
            message=incident.description or "",
            metadata={"incident_id": new_incident.id}
        )
    except Exception:
        # non-fatal
        pass

    return IncidentResponse(
        id=new_incident.id,
        title=new_incident.title,
        description=new_incident.description,
        severity=new_incident.severity,
        status=new_incident.status,
        metadata=new_incident.meta,
        created_at=new_incident.created_at
    )


@router.get("/incidents", response_model=List[IncidentResponse])
async def list_incidents(
    skip: int = 0,
    limit: int = 50,
    status_filter: Optional[str] = None,
    severity: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    from app.models import Incident as IncidentModel

    query = select(IncidentModel).offset(skip).limit(limit)
    if status_filter:
        query = query.where(IncidentModel.status == status_filter)
    if severity:
        query = query.where(IncidentModel.severity == severity)

    result = await db.execute(query)
    incidents = result.scalars().all()

    return [
        IncidentResponse(
            id=i.id,
            title=i.title,
            description=i.description,
            severity=i.severity,
            status=i.status,
            metadata=i.meta,
            created_at=i.created_at
        )
        for i in incidents
    ]


@router.get("/incidents/{incident_id}", response_model=IncidentDetailResponse)
async def get_incident(
    incident_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    from app.models import Incident as IncidentModel, AttackLog as AttackLogModel

    result = await db.execute(select(IncidentModel).where(IncidentModel.id == incident_id))
    incident = result.scalar_one_or_none()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    meta = incident.meta or {}
    attack_ids = meta.get("attack_ids") or []
    if not isinstance(attack_ids, list):
        attack_ids = []

    attacks: list[AttackLog] = []
    if attack_ids:
        attack_result = await db.execute(
            select(AttackLogModel)
            .where(AttackLogModel.id.in_(attack_ids))
            .order_by(desc(AttackLogModel.timestamp))
        )
        attacks = attack_result.scalars().all()

    related_attack_types = sorted({attack.attack_type for attack in attacks})
    related_ips = sorted({attack.ip_address for attack in attacks})
    event_count = int(meta.get("event_count", len(attacks)))
    first_seen_raw = meta.get("first_seen")
    last_seen_raw = meta.get("last_seen")

    def _parse_dt(value: Optional[str]):
        if not value:
            return None
        try:
            return datetime.fromisoformat(value)
        except Exception:
            return None

    risk_score = min(100, 15 + (event_count * 15) + (10 if incident.severity in {"high", "critical"} else 0))

    return IncidentDetailResponse(
        id=incident.id,
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        status=incident.status,
        metadata=incident.meta,
        created_at=incident.created_at,
        fingerprint=meta.get("fingerprint"),
        event_count=event_count,
        risk_score=risk_score,
        first_seen=_parse_dt(first_seen_raw),
        last_seen=_parse_dt(last_seen_raw),
        related_attack_types=related_attack_types,
        related_ips=related_ips,
        attacks=[
            IncidentAttackSummary(
                id=attack.id,
                attack_type=attack.attack_type,
                severity=attack.severity,
                detection_method=attack.detection_method,
                ip_address=attack.ip_address,
                timestamp=attack.timestamp,
                payload=attack.payload,
            )
            for attack in attacks
        ],
    )


@router.post("/incidents/{incident_id}/resolve", response_model=IncidentResponse)
async def resolve_incident(
    incident_id: int,
    request: IncidentResolveRequest | None = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    from app.models import Incident as IncidentModel

    result = await db.execute(select(IncidentModel).where(IncidentModel.id == incident_id))
    incident = result.scalar_one_or_none()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    if incident.status == "resolved":
        return IncidentResponse(
            id=incident.id,
            title=incident.title,
            description=incident.description,
            severity=incident.severity,
            status=incident.status,
            metadata=incident.meta,
            created_at=incident.created_at,
        )

    meta = dict(incident.meta or {})
    meta["resolved_at"] = datetime.utcnow().isoformat()
    meta["resolved_by"] = current_user.id
    if request and request.resolution_note:
        meta["resolution_note"] = request.resolution_note

    incident.status = "resolved"
    incident.meta = meta
    incident.updated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(incident)

    await log_service.log_audit(
        db,
        user_id=current_user.id,
        action="incident_resolved",
        resource="incidents",
        details={"incident_id": incident.id, "title": incident.title, "resolution_note": meta.get("resolution_note")}
    )

    try:
        await alert_service.create_alert(
            db,
            alert_type="incident",
            severity="low",
            title=f"Incident Resolved: {incident.title}",
            message=request.resolution_note if request and request.resolution_note else "Incident marked as resolved.",
            metadata={"incident_id": incident.id, "resolved": True}
        )
    except Exception:
        pass

    return IncidentResponse(
        id=incident.id,
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        status=incident.status,
        metadata=incident.meta,
        created_at=incident.created_at,
    )


class NotificationSendRequest(BaseModel):
    user_id: int
    title: str
    message: str
    notification_type: str = "info"
    target: Optional[str] = None


@router.post("/notifications/send")
async def send_notification(
    body: NotificationSendRequest,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    from app.models import Notification as NotificationModel
    from app.config import settings
    from app.notification import enqueue_notification_delivery

    note = NotificationModel(
        user_id=body.user_id,
        title=body.title,
        message=body.message,
        notification_type=body.notification_type,
        delivery_status="queued",
        delivery_target=body.target,
    )
    db.add(note)
    await db.commit()
    await db.refresh(note)

    await log_service.log_audit(
        db,
        user_id=current_user.id,
        action="notification_sent",
        resource="notifications",
        details={"notification_id": note.id, "user_id": body.user_id}
    )

    try:
        delivery_target = body.target or getattr(settings, "NOTIFICATION_WEBHOOK", None)
        await enqueue_notification_delivery(
            http_request.app,
            note.id,
            {
                "notification_id": note.id,
                "title": body.title,
                "message": body.message,
                "user_id": body.user_id,
                "notification_type": body.notification_type,
            },
            target=delivery_target,
            max_attempts=4,
        )
    except Exception:
        pass

    return {"status": "queued", "id": note.id, "delivery_target": body.target or getattr(settings, "NOTIFICATION_WEBHOOK", None)}


class ActivityItem(BaseModel):
    id: int
    type: str
    created_at: datetime
    details: dict


@router.get("/activity", response_model=List[ActivityItem])
async def get_activity(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not permission_checker.has_permission(
        permission_checker.get_permissions(current_user.role.value),
        "activity:read"
    ):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    from app.models import NotificationDeliveryAttempt as NDA, Notification as NotificationModel, Incident as IncidentModel

    # Fetch recent notification delivery attempts
    nd_result = await db.execute(
        select(NDA).order_by(desc(NDA.created_at)).limit(limit)
    )
    attempts = nd_result.scalars().all()

    items: List[ActivityItem] = []
    for a in attempts:
        notif = None
        try:
            notif_res = await db.execute(select(NotificationModel).where(NotificationModel.id == a.notification_id))
            notif = notif_res.scalar_one_or_none()
        except Exception:
            notif = None

        details = {
            "notification_id": a.notification_id,
            "target": a.target,
            "attempt_number": a.attempt_number,
            "status": a.status,
            "error_message": a.error_message,
            "response_code": a.response_code,
        }
        if notif:
            details["title"] = notif.title

        items.append(ActivityItem(id=a.id, type="notification_attempt", created_at=a.created_at, details=details))

    # If we have space, include recent incident updates
    remaining = max(0, limit - len(items))
    if remaining > 0:
        inc_result = await db.execute(
            select(IncidentModel).order_by(desc(IncidentModel.updated_at)).limit(remaining)
        )
        incidents = inc_result.scalars().all()
        for inc in incidents:
            details = {
                "incident_id": inc.id,
                "title": inc.title,
                "severity": inc.severity,
                "status": inc.status,
            }
            items.append(ActivityItem(id=inc.id * 1000000, type="incident", created_at=inc.updated_at or inc.created_at, details=details))

    # Sort combined items by created_at desc and limit
    items_sorted = sorted(items, key=lambda x: x.created_at or datetime.utcnow(), reverse=True)

    return items_sorted[:limit]


@router.post('/admin/config/apply')
async def apply_admin_config(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    # admin-only
    if current_user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN):
        raise HTTPException(status_code=403, detail='Insufficient permissions')

    # mark last_applied in global config
    try:
        from app.models import GlobalConfig as GC
        stmt = select(GC).where(GC.key == '__last_applied__')
        res = await db.execute(stmt)
        obj = res.scalar_one_or_none()
        now = datetime.utcnow().isoformat()
        if obj:
            obj.value = {'applied_at': now, 'by': current_user.id}
            obj.version = (obj.version or 1) + 1
            obj.updated_by = current_user.id
            db.add(obj)
        else:
            new = GC(key='__last_applied__', value={'applied_at': now, 'by': current_user.id}, encrypted=False, updated_by=current_user.id)
            db.add(new)
        await db.commit()
    except Exception:
        try:
            await db.rollback()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail='Failed to record apply')

    await log_service.log_audit(db, user_id=current_user.id, tenant_id=current_user.tenant_id, action='apply_global_config', resource='global_config', details={'by': current_user.id})

    # Optional remote restart: only if env var ALLOW_REMOTE_RESTART is truthy
    import os, asyncio
    allow_restart = os.getenv('ALLOW_REMOTE_RESTART', 'false').lower() in ('1', 'true', 'yes')
    if allow_restart:
        async def delayed_exit():
            await asyncio.sleep(1.0)
            os._exit(0)

        asyncio.create_task(delayed_exit())
        return {"status": "applied", "restart": True}

    return {"status": "applied", "restart": False}