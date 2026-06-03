from datetime import datetime, timedelta
from celery import shared_task
from sqlalchemy import select, delete
from app.database import AsyncSessionLocal
from app.models import RefreshToken, ActiveSession, CapabilityToken, AttackLog, AuditLog
import logging

logger = logging.getLogger(__name__)


@shared_task(bind=True, name="app.tasks.cleanup.cleanup_expired_tokens")
def cleanup_expired_tokens(self):
    async def _cleanup():
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                delete(RefreshToken).where(RefreshToken.expires_at < datetime.utcnow())
            )
            
            deleted_count = result.rowcount
            await db.commit()
            
            logger.info(f"Cleaned up {deleted_count} expired refresh tokens")
            
            return {"deleted_tokens": deleted_count}
    
    import asyncio
    return asyncio.run(_cleanup())


@shared_task(bind=True, name="app.tasks.cleanup.cleanup_expired_sessions")
def cleanup_expired_sessions(self):
    async def _cleanup():
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                delete(ActiveSession).where(ActiveSession.expires_at < datetime.utcnow())
            )
            
            deleted_count = result.rowcount
            await db.commit()
            
            logger.info(f"Cleaned up {deleted_count} expired sessions")
            
            return {"deleted_sessions": deleted_count}
    
    import asyncio
    return asyncio.run(_cleanup())


@shared_task(bind=True, name="app.tasks.cleanup.cleanup_expired_capabilities")
def cleanup_expired_capabilities(self):
    async def _cleanup():
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                delete(CapabilityToken).where(CapabilityToken.expires_at < datetime.utcnow())
            )
            
            deleted_count = result.rowcount
            await db.commit()
            
            logger.info(f"Cleaned up {deleted_count} expired capability tokens")
            
            return {"deleted_capabilities": deleted_count}
    
    import asyncio
    return asyncio.run(_cleanup())


@shared_task(bind=True, name="app.tasks.cleanup.cleanup_old_logs")
def cleanup_old_logs(self, retention_days: int = 90):
    async def _cleanup():
        async with AsyncSessionLocal() as db:
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
            
            attack_deleted = await db.execute(
                delete(AttackLog).where(AttackLog.timestamp < cutoff_date)
            )
            
            audit_deleted = await db.execute(
                delete(AuditLog).where(AuditLog.timestamp < cutoff_date)
            )
            
            await db.commit()
            
            logger.info(f"Cleaned up {attack_deleted.rowcount} old attack logs and {audit_deleted.rowcount} audit logs")
            
            return {
                "deleted_attack_logs": attack_deleted.rowcount,
                "deleted_audit_logs": audit_deleted.rowcount,
                "retention_days": retention_days
            }
    
    import asyncio
    return asyncio.run(_cleanup())


@shared_task(bind=True, name="app.tasks.cleanup.cleanup_duplicate_alerts")
def cleanup_duplicate_alerts(self):
    async def _cleanup():
        from app.models import SystemAlert
        from sqlalchemy import func
        
        async with AsyncSessionLocal() as db:
            subquery = (
                select(SystemAlert.title, SystemAlert.alert_type, func.max(SystemAlert.id).label("max_id"))
                .where(SystemAlert.is_resolved == False)
                .group_by(SystemAlert.title, SystemAlert.alert_type)
                .having(func.count(SystemAlert.id) > 1)
            )
            
            result = await db.execute(subquery)
            duplicate_groups = result.all()
            
            deleted_count = 0
            
            for title, alert_type, max_id in duplicate_groups:
                duplicates = await db.execute(
                    delete(SystemAlert)
                    .where(
                        SystemAlert.title == title,
                        SystemAlert.alert_type == alert_type,
                        SystemAlert.is_resolved == False,
                        SystemAlert.id < max_id
                    )
                )
                deleted_count += duplicates.rowcount
            
            await db.commit()
            
            logger.info(f"Cleaned up {deleted_count} duplicate alerts")
            
            return {"deleted_duplicates": deleted_count}
    
    import asyncio
    return asyncio.run(_cleanup())


@shared_task(bind=True, name="app.tasks.cleanup.cleanup_blocked_ips")
def cleanup_blocked_ips(self):
    async def _cleanup():
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                delete(BlockedIP).where(
                    BlockedIP.is_permanent == False,
                    BlockedIP.expires_at < datetime.utcnow()
                )
            )
            
            deleted_count = result.rowcount
            await db.commit()
            
            logger.info(f"Cleaned up {deleted_count} expired blocked IPs")
            
            return {"deleted_expired_ips": deleted_count}
    
    import asyncio
    return asyncio.run(_cleanup())