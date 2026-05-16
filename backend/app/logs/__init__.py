from datetime import datetime, timedelta
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, and_, or_
from hashlib import sha256
from app.models import (
    AttackLog, QueryLog, EncryptionLog, FailedLoginAttempt,
    AuditLog, Notification, SecurityMetric, SystemAlert, BlockedIP
)
import json


class LogService:
    @staticmethod
    def _severity_rank(severity: Optional[str]) -> int:
        order = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4,
        }
        return order.get((severity or 'medium').lower(), 2)

    @staticmethod
    def _build_incident_fingerprint(ip_address: str, attack_type: str, target: Optional[str], detection_method: Optional[str]) -> str:
        source = f"{ip_address}|{attack_type}|{target or ''}|{detection_method or ''}".lower().strip()
        return sha256(source.encode('utf-8')).hexdigest()

    @staticmethod
    def _normalize_incident_meta(meta: Optional[dict]) -> dict:
        normalized = dict(meta or {})
        normalized.setdefault('attack_ids', [])
        normalized.setdefault('event_count', 0)
        return normalized

    @staticmethod
    async def correlate_incident(db: AsyncSession, attack_log: AttackLog):
        from app.models import Incident

        fingerprint = LogService._build_incident_fingerprint(
            attack_log.ip_address,
            attack_log.attack_type,
            attack_log.target,
            attack_log.detection_method,
        )

        window_start = (attack_log.timestamp or datetime.utcnow()) - timedelta(hours=1)

        recent_result = await db.execute(
            select(AttackLog)
            .where(AttackLog.ip_address == attack_log.ip_address)
            .where(AttackLog.attack_type == attack_log.attack_type)
            .where(AttackLog.timestamp >= window_start)
            .order_by(desc(AttackLog.timestamp))
        )
        recent_attacks = recent_result.scalars().all()
        recent_attack_ids = [a.id for a in recent_attacks if getattr(a, 'id', None) is not None]
        if attack_log.id is not None and attack_log.id not in recent_attack_ids:
            recent_attack_ids.insert(0, attack_log.id)

        should_create_or_update = (
            LogService._severity_rank(attack_log.severity) >= LogService._severity_rank('high')
            or len(recent_attack_ids) >= 3
        )
        if not should_create_or_update:
            return None

        open_result = await db.execute(
            select(Incident)
            .where(Incident.status == 'open')
            .order_by(desc(Incident.created_at))
        )
        open_incidents = open_result.scalars().all()

        matching_incident = None
        for incident in open_incidents:
            incident_meta = LogService._normalize_incident_meta(incident.meta)
            if incident_meta.get('fingerprint') == fingerprint:
                matching_incident = incident
                break

        current_ts = (attack_log.timestamp or datetime.utcnow()).isoformat()
        base_title = f"Correlated attacks from {attack_log.ip_address}"
        base_description = (
            f"{len(recent_attack_ids)} attacks from {attack_log.ip_address} matching {attack_log.attack_type} "
            f"were observed in the last hour."
        )

        if matching_incident is not None:
            incident_meta = LogService._normalize_incident_meta(matching_incident.meta)
            incident_meta.update({
                'fingerprint': fingerprint,
                'ip_address': attack_log.ip_address,
                'attack_type': attack_log.attack_type,
                'target': attack_log.target,
                'detection_method': attack_log.detection_method,
                'first_seen': incident_meta.get('first_seen') or current_ts,
                'last_seen': current_ts,
                'attack_ids': sorted(set(incident_meta.get('attack_ids', []) + recent_attack_ids)),
                'event_count': max(
                    int(incident_meta.get('event_count', 0)),
                    len(sorted(set(incident_meta.get('attack_ids', []) + recent_attack_ids)))
                ),
            })
            matching_incident.meta = incident_meta
            matching_incident.title = matching_incident.title or base_title
            if LogService._severity_rank(attack_log.severity) > LogService._severity_rank(matching_incident.severity):
                matching_incident.severity = attack_log.severity
            matching_incident.description = matching_incident.description or base_description
            matching_incident.updated_at = attack_log.timestamp or datetime.utcnow()
            await db.commit()
            await db.refresh(matching_incident)
            return matching_incident

        from app.models import Incident as IncidentModel

        new_incident = IncidentModel(
            title=base_title,
            description=base_description,
            severity=attack_log.severity if LogService._severity_rank(attack_log.severity) >= LogService._severity_rank('high') else 'medium',
            status='open',
            meta={
                'fingerprint': fingerprint,
                'ip_address': attack_log.ip_address,
                'attack_type': attack_log.attack_type,
                'target': attack_log.target,
                'detection_method': attack_log.detection_method,
                'first_seen': current_ts,
                'last_seen': current_ts,
                'attack_ids': recent_attack_ids,
                'event_count': len(recent_attack_ids),
            },
        )
        db.add(new_incident)
        await db.commit()
        await db.refresh(new_incident)

        try:
            await alert_service.create_alert(
                db,
                alert_type='incident',
                severity=new_incident.severity,
                title=f'Incident: {new_incident.title}',
                message=new_incident.description or '',
                metadata={'incident_id': new_incident.id, 'fingerprint': fingerprint},
            )
        except Exception:
            pass

        return new_incident

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
            meta=metadata
        )
        db.add(attack_log)
        await db.commit()
        # refresh to populate id/timestamp
        await db.refresh(attack_log)

        # Broadcast the attack to any connected websocket clients (best-effort)
        try:
            from app.main import broadcast_attack, publish_app_event

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

            # Publish through shared app event helper so Redis or local fallback both work
            try:
                from app.main import app as fastapi_app
                published = await publish_app_event(fastapi_app, 'ws:attacks', attack_data)
                if not published:
                    await broadcast_attack(attack_data)
            except Exception:
                # Best-effort: don't let broadcasting break logging
                try:
                    await broadcast_attack(attack_data)
                except Exception:
                    pass
        except Exception:
            # If broadcast fails for any reason, ignore to not break logging
            pass

        # Correlate repeated/high-severity attacks into a synchronous incident.
        try:
            await LogService.correlate_incident(db, attack_log)
        except Exception:
            pass

        # Publish cache invalidation to Redis (best-effort)
        try:
            from app.main import app as fastapi_app, publish_app_event

            await publish_app_event(
                fastapi_app,
                'cache:security:invalidate',
                {"attack_id": attack_log.id, "timestamp": attack_log.timestamp.isoformat()}
            )
        except Exception:
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
        blocked: bool = None,
        search: str = None,
        start_time: datetime = None,
        end_time: datetime = None
    ):
        attack_query = select(AttackLog).order_by(desc(AttackLog.timestamp))
        
        if attack_type:
            attack_query = attack_query.where(AttackLog.attack_type == attack_type)
        if severity:
            attack_query = attack_query.where(AttackLog.severity == severity)
        if blocked is not None:
            attack_query = attack_query.where(AttackLog.blocked == blocked)
        if search:
            like = f"%{search}%"
            attack_query = attack_query.where(
                or_(
                    AttackLog.attack_type.ilike(like),
                    AttackLog.payload.ilike(like),
                    AttackLog.ip_address.ilike(like),
                    AttackLog.target.ilike(like),
                    AttackLog.detection_method.ilike(like),
                )
            )
        if start_time is not None:
            attack_query = attack_query.where(AttackLog.timestamp >= start_time)
        if end_time is not None:
            attack_query = attack_query.where(AttackLog.timestamp <= end_time)
        
        attack_query = attack_query.limit(limit).offset(offset)
        
        result = await db.execute(attack_query)
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