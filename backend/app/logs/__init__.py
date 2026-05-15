from datetime import datetime
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, and_
from app.models import (
    AttackLog, QueryLog, EncryptionLog, FailedLoginAttempt,
    AuditLog, Notification, SecurityMetric, SystemAlert, BlockedIP
)
import json


class LogService:
    @staticmethod
    async def log_attack(
        db: AsyncSession,
        user_id: Optional[int],
        ip_address: str,
        attack_type: str,
        payload: str,
        target: str,
        severity: str,
        detection_method: str,
        blocked: bool = True,
        metadata: dict = None
    ):
        attack_log = AttackLog(
            user_id=user_id,
            ip_address=ip_address,
            attack_type=attack_type,
            payload=payload[:5000],
            target=target,
            severity=severity,
            detection_method=detection_method,
            blocked=blocked,
            metadata=metadata
        )
        db.add(attack_log)
        await db.commit()
        # refresh to populate id/timestamp
        await db.refresh(attack_log)

        # Broadcast the attack to any connected websocket clients (best-effort)
        try:
            from app.main import broadcast_attack

            attack_data = {
                "id": attack_log.id,
                "user_id": attack_log.user_id,
                "ip_address": attack_log.ip_address,
                "attack_type": attack_log.attack_type,
                "payload": attack_log.payload,
                "target": attack_log.target,
                "severity": attack_log.severity,
                "detection_method": attack_log.detection_method,
                "blocked": attack_log.blocked,
                "timestamp": attack_log.timestamp.isoformat()
            }

            # fire-and-forget
            try:
                import asyncio
                asyncio.create_task(broadcast_attack(attack_data))
            except Exception:
                # fallback: call synchronously
                await broadcast_attack(attack_data)
        except Exception:
            # If broadcast fails for any reason, ignore to not break logging
            pass

        return attack_log
    
    @staticmethod
    async def log_query(
        db: AsyncSession,
        user_id: Optional[int],
        query: str,
        parameters: dict = None,
        execution_time: float = None,
        ip_address: str = None,
        blocked: bool = False,
        block_reason: str = None
    ):
        query_log = QueryLog(
            user_id=user_id,
            query=query[:10000],
            parameters=parameters,
            execution_time=execution_time,
            ip_address=ip_address,
            blocked=blocked,
            block_reason=block_reason
        )
        db.add(query_log)
        await db.commit()
        return query_log
    
    @staticmethod
    async def log_encryption(
        db: AsyncSession,
        operation_type: str,
        data_type: str = None,
        success: bool = True,
        metadata: dict = None
    ):
        log = EncryptionLog(
            operation_type=operation_type,
            data_type=data_type,
            success=success,
            metadata=metadata
        )
        db.add(log)
        await db.commit()
        return log
    
    @staticmethod
    async def log_failed_login(
        db: AsyncSession,
        email: str,
        ip_address: str,
        user_agent: str = None
    ):
        result = await db.execute(
            select(FailedLoginAttempt)
            .where(FailedLoginAttempt.email == email)
            .where(FailedLoginAttempt.ip_address == ip_address)
        )
        existing = result.scalar_one_or_none()
        
        if existing:
            existing.attempts += 1
            existing.timestamp = datetime.utcnow()
        else:
            failed_login = FailedLoginAttempt(
                email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                attempts=1
            )
            db.add(failed_login)
        
        await db.commit()
    
    @staticmethod
    async def log_audit(
        db: AsyncSession,
        user_id: Optional[int],
        action: str,
        resource: str = None,
        details: dict = None,
        ip_address: str = None
    ):
        audit = AuditLog(
            user_id=user_id,
            action=action,
            resource=resource,
            details=details,
            ip_address=ip_address
        )
        db.add(audit)
        await db.commit()
        return audit
    
    @staticmethod
    async def get_attack_logs(
        db: AsyncSession,
        limit: int = 100,
        offset: int = 0,
        attack_type: str = None,
        severity: str = None,
        blocked: bool = None
    ):
        query = select(AttackLog).order_by(desc(AttackLog.timestamp))
        
        if attack_type:
            query = query.where(AttackLog.attack_type == attack_type)
        if severity:
            query = query.where(AttackLog.severity == severity)
        if blocked is not None:
            query = query.where(AttackLog.blocked == blocked)
        
        query = query.limit(limit).offset(offset)
        
        result = await db.execute(query)
        return result.scalars().all()
    
    @staticmethod
    async def get_security_metrics(
        db: AsyncSession,
        hours: int = 24
    ):
        from datetime import timedelta
        from sqlalchemy import func
        
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        result = await db.execute(
            select(SecurityMetric)
            .where(SecurityMetric.timestamp >= start_time)
            .order_by(desc(SecurityMetric.timestamp))
        )
        return result.scalars().all()


class AlertService:
    @staticmethod
    async def create_alert(
        db: AsyncSession,
        alert_type: str,
        severity: str,
        title: str,
        message: str,
        metadata: dict = None
    ):
        alert = SystemAlert(
            alert_type=alert_type,
            severity=severity,
            title=title,
            message=message,
            metadata=metadata
        )
        db.add(alert)
        await db.commit()
        
        if severity in ['critical', 'high']:
            await AlertService._notify_admins(db, title, message, severity)
        
        return alert
    
    @staticmethod
    async def _notify_admins(db: AsyncSession, title: str, message: str, severity: str):
        from app.models import User, UserRole
        
        result = await db.execute(
            select(User).where(User.role.in_([UserRole.ADMIN, UserRole.SUPER_ADMIN]))
        )
        admins = result.scalars().all()
        
        for admin in admins:
            notification = Notification(
                user_id=admin.id,
                title=f"Security Alert: {title}",
                message=message,
                notification_type="security"
            )
            db.add(notification)
        
        await db.commit()
    
    @staticmethod
    async def get_active_alerts(db: AsyncSession):
        result = await db.execute(
            select(SystemAlert)
            .where(SystemAlert.is_resolved == False)
            .order_by(desc(SystemAlert.created_at))
        )
        return result.scalars().all()
    
    @staticmethod
    async def resolve_alert(db: AsyncSession, alert_id: int):
        result = await db.execute(
            select(SystemAlert).where(SystemAlert.id == alert_id)
        )
        alert = result.scalar_one_or_none()
        
        if alert:
            alert.is_resolved = True
            alert.resolved_at = datetime.utcnow()
            await db.commit()
        
        return alert


class IPBlocker:
    @staticmethod
    async def block_ip(
        db: AsyncSession,
        ip_address: str,
        reason: str = None,
        is_permanent: bool = False,
        expires_at: datetime = None
    ):
        result = await db.execute(
            select(BlockedIP).where(BlockedIP.ip_address == ip_address)
        )
        existing = result.scalar_one_or_none()
        
        if existing:
            existing.is_permanent = is_permanent
            existing.expires_at = expires_at
            existing.reason = reason
        else:
            blocked = BlockedIP(
                ip_address=ip_address,
                reason=reason,
                is_permanent=is_permanent,
                expires_at=expires_at
            )
            db.add(blocked)
        
        await db.commit()
        return existing or blocked
    
    @staticmethod
    async def is_blocked(db: AsyncSession, ip_address: str) -> bool:
        result = await db.execute(
            select(BlockedIP).where(BlockedIP.ip_address == ip_address)
        )
        blocked = result.scalar_one_or_none()
        
        if not blocked:
            return False
        
        if blocked.is_permanent:
            return True
        
        if blocked.expires_at and datetime.utcnow() > blocked.expires_at:
            return False
        
        return True
    
    @staticmethod
    async def unblock_ip(db: AsyncSession, ip_address: str):
        result = await db.execute(
            select(BlockedIP).where(BlockedIP.ip_address == ip_address)
        )
        blocked = result.scalar_one_or_none()
        
        if blocked:
            await db.delete(blocked)
            await db.commit()
        
        return blocked is not None


log_service = LogService()
alert_service = AlertService()
ip_blocker = IPBlocker()