from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr
from app.database import get_db
from app.models import User, UserRole, AttackLog, SystemAlert, SecurityMetric, BlockedIP, AIDetectionResult
from app.auth import auth_service, get_current_user, get_password_hash
from app.config import settings
import pyotp
from app.capability import capability_manager, permission_checker
from app.detection import sql_injection_detector, Severity
from app.ai_detection import ai_detector
from app.logs import log_service, alert_service, ip_blocker
from app.encryption import encryption_service


router = APIRouter()


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str = "user"


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    is_verified: bool
    last_login: Optional[datetime] = None
    created_at: datetime


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
        role
    )
    
    await log_service.log_audit(
        db,
        user_id=user.id,
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
        action="user_login",
        resource="auth",
        details={"username": user.username}
    )
    
    return auth_service.create_tokens(user)


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
        role=current_user.role.value,
        is_active=current_user.is_active,
        is_verified=current_user.is_verified,
        last_login=current_user.last_login,
        created_at=current_user.created_at
    )


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
        detection_method=result.detection_method
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
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not permission_checker.has_permission(
        permission_checker.get_permissions(current_user.role.value),
        "logs:read"
    ):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    logs = await log_service.get_attack_logs(
        db, limit, skip, attack_type, severity
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
        # Cache result in Redis for short period
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
                    "timeseries": timeseries
                }
                await redis.set(cache_key, orjson.dumps(payload), ex=15)
        except Exception:
            pass


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