from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from datetime import datetime
from typing import Optional, List
import io
import csv
import json

from app.database import get_db
from app.models import User, ActiveSession, AttackLog, BlockedIP, AuditLog
from app.auth import get_current_user
from app.capability import permission_checker
from app.config import settings

router = APIRouter()


class SessionResponse(BaseModel):
    id: int
    session_id: str
    ip_address: str
    user_agent: Optional[str]
    created_at: datetime
    expires_at: datetime
    is_active: bool


class ExportRequest(BaseModel):
    format: str = "json"
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    entity_type: str = "attacks"


@router.get("/sessions", response_model=List[dict])
async def list_sessions(
    user_id: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not permission_checker.has_permission(
        permission_checker.get_permissions(current_user.role.value),
        "users:read"
    ):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    query = select(ActiveSession).order_by(ActiveSession.created_at.desc())
    
    if user_id:
        query = query.where(ActiveSession.user_id == user_id)
    else:
        if current_user.role.value not in ['admin', 'super_admin']:
            query = query.where(ActiveSession.user_id == current_user.id)
    
    result = await db.execute(query.limit(100))
    sessions = result.scalars().all()
    
    return [
        {
            "id": s.id,
            "session_id": s.session_id,
            "ip_address": s.ip_address,
            "user_agent": s.user_agent,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "expires_at": s.expires_at.isoformat() if s.expires_at else None,
            "is_active": s.is_active
        }
        for s in sessions
    ]


@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(ActiveSession).where(ActiveSession.session_id == session_id)
    )
    session = result.scalar_one_or_none()
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if current_user.role.value not in ['admin', 'super_admin']:
        if session.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Cannot revoke other user's session")
    
    session.is_active = False
    await db.commit()
    
    return {"status": "revoked", "session_id": session_id}


@router.delete("/sessions/user/{user_id}")
async def revoke_all_user_sessions(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if current_user.role.value not in ['admin', 'super_admin']:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    result = await db.execute(
        delete(ActiveSession).where(ActiveSession.user_id == user_id)
    )
    
    await db.commit()
    
    return {"status": "revoked", "count": result.rowcount}


@router.get("/export/attacks")
async def export_attacks(
    format: str = "json",
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not permission_checker.has_permission(
        permission_checker.get_permissions(current_user.role.value),
        "logs:read"
    ):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    query = select(AttackLog).order_by(AttackLog.timestamp.desc()).limit(10000)
    
    if start_date:
        query = query.where(AttackLog.timestamp >= datetime.fromisoformat(start_date))
    if end_date:
        query = query.where(AttackLog.timestamp <= datetime.fromisoformat(end_date))
    
    result = await db.execute(query)
    logs = result.scalars().all()
    
    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "ID", "Timestamp", "User ID", "IP Address", "Attack Type",
            "Severity", "Blocked", "Detection Method", "Target", "Payload"
        ])
        
        for log in logs:
            writer.writerow([
                log.id,
                log.timestamp.isoformat() if log.timestamp else "",
                log.user_id or "",
                log.ip_address,
                log.attack_type,
                log.severity,
                log.blocked,
                log.detection_method,
                log.target or "",
                (log.payload or "")[:500]
            ])
        
        output.seek(0)
        
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=attacks_{datetime.utcnow().date()}.csv"}
        )
    
    else:
        data = [
            {
                "id": log.id,
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                "user_id": log.user_id,
                "ip_address": log.ip_address,
                "attack_type": log.attack_type,
                "severity": log.severity,
                "blocked": log.blocked,
                "detection_method": log.detection_method,
                "target": log.target,
                "payload": (log.payload or "")[:1000]
            }
            for log in logs
        ]
        
        return StreamingResponse(
            iter([json.dumps(data, indent=2)]),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=attacks_{datetime.utcnow().date()}.json"}
        )


@router.get("/export/blocked-ips")
async def export_blocked_ips(
    format: str = "json",
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not permission_checker.has_permission(
        permission_checker.get_permissions(current_user.role.value),
        "security:read"
    ):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    result = await db.execute(select(BlockedIP).order_by(BlockedIP.blocked_at.desc()))
    ips = result.scalars().all()
    
    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["IP Address", "Reason", "Blocked At", "Expires At", "Permanent"])
        
        for ip in ips:
            writer.writerow([
                ip.ip_address,
                ip.reason or "",
                ip.blocked_at.isoformat() if ip.blocked_at else "",
                ip.expires_at.isoformat() if ip.expires_at else "",
                ip.is_permanent
            ])
        
        output.seek(0)
        
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=blocked_ips_{datetime.utcnow().date()}.csv"}
        )
    
    data = [
        {
            "ip_address": ip.ip_address,
            "reason": ip.reason,
            "blocked_at": ip.blocked_at.isoformat() if ip.blocked_at else None,
            "expires_at": ip.expires_at.isoformat() if ip.expires_at else None,
            "is_permanent": ip.is_permanent
        }
        for ip in ips
    ]
    
    return StreamingResponse(
        iter([json.dumps(data, indent=2)]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=blocked_ips_{datetime.utcnow().date()}.json"}
    )


@router.post("/import/blocked-ips")
async def import_blocked_ips(
    ips: List[dict],
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not permission_checker.has_permission(
        permission_checker.get_permissions(current_user.role.value),
        "security:write"
    ):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    imported = 0
    skipped = 0
    
    for ip_data in ips:
        ip_address = ip_data.get("ip_address")
        reason = ip_data.get("reason", "Bulk import")
        is_permanent = ip_data.get("is_permanent", False)
        
        if not ip_address:
            skipped += 1
            continue
        
        existing = await db.execute(
            select(BlockedIP).where(BlockedIP.ip_address == ip_address)
        )
        
        if existing.scalar_one_or_none():
            skipped += 1
            continue
        
        blocked = BlockedIP(
            ip_address=ip_address,
            reason=reason,
            is_permanent=is_permanent
        )
        db.add(blocked)
        imported += 1
    
    await db.commit()
    
    return {
        "imported": imported,
        "skipped": skipped,
        "total": len(ips)
    }


@router.get("/export/audit-logs")
async def export_audit_logs(
    format: str = "json",
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not permission_checker.has_permission(
        permission_checker.get_permissions(current_user.role.value),
        "logs:read"
    ):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    query = select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(5000)
    
    if start_date:
        query = query.where(AuditLog.timestamp >= datetime.fromisoformat(start_date))
    if end_date:
        query = query.where(AuditLog.timestamp <= datetime.fromisoformat(end_date))
    
    result = await db.execute(query)
    logs = result.scalars().all()
    
    data = [
        {
            "id": log.id,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "user_id": log.user_id,
            "action": log.action,
            "resource": log.resource,
            "details": log.details,
            "ip_address": log.ip_address
        }
        for log in logs
    ]
    
    return StreamingResponse(
        iter([json.dumps(data, indent=2)]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=audit_logs_{datetime.utcnow().date()}.json"}
    )


@router.get("/stats/overview")
async def get_stats_overview(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    from sqlalchemy import func
    
    if not permission_checker.has_permission(
        permission_checker.get_permissions(current_user.role.value),
        "analytics:read"
    ):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    total_users = await db.execute(select(func.count(User.id)))
    active_users = await db.execute(
        select(func.count(User.id)).where(User.is_active == True)
    )
    
    total_attacks = await db.execute(select(func.count(AttackLog.id)))
    blocked_ips = await db.execute(select(func.count(BlockedIP.id)))
    
    from app.models import SystemAlert
    active_alerts = await db.execute(
        select(func.count(SystemAlert.id)).where(SystemAlert.is_resolved == False)
    )
    
    return {
        "users": {
            "total": total_users.scalar() or 0,
            "active": active_users.scalar() or 0
        },
        "security": {
            "total_attacks": total_attacks.scalar() or 0,
            "blocked_ips": blocked_ips.scalar() or 0,
            "active_alerts": active_alerts.scalar() or 0
        }
    }