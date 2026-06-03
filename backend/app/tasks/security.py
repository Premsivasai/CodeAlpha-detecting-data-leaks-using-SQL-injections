import logging
from datetime import datetime, timedelta
from celery import shared_task
from sqlalchemy import select, func
from app.database import AsyncSessionLocal
from app.models import AttackLog, BlockedIP
from app.threat_intel import threat_intel_service

logger = logging.getLogger(__name__)


@shared_task(bind=True, name="app.tasks.security.sync_threat_intel")
def sync_threat_intel(self):
    async def _sync():
        async with AsyncSessionLocal() as db:
            recent_attacks = await db.execute(
                select(AttackLog.ip_address, func.count(AttackLog.id))
                .where(AttackLog.timestamp >= datetime.utcnow() - timedelta(hours=24))
                .group_by(AttackLog.ip_address)
                .having(func.count(AttackLog.id) > 5)
            )
            
            processed = 0
            blocked = 0
            
            for ip, count in recent_attacks.all():
                result = await threat_intel_service.check_ip_reputation(ip)
                
                if result.is_malicious:
                    existing = await db.execute(
                        select(BlockedIP).where(BlockedIP.ip_address == ip)
                    )
                    
                    if not existing.scalar_one_or_none():
                        blocked_ip = BlockedIP(
                            ip_address=ip,
                            reason=f"Auto-blocked by threat intelligence: {', '.join(result.threat_categories)}",
                            is_permanent=False,
                            expires_at=datetime.utcnow() + timedelta(days=7)
                        )
                        db.add(blocked_ip)
                        blocked += 1
                
                processed += 1
            
            await db.commit()
            
            return {
                "processed_ips": processed,
                "auto_blocked": blocked,
                "timestamp": datetime.utcnow().isoformat()
            }
    
    import asyncio
    return asyncio.run(_sync())


@shared_task(bind=True, name="app.tasks.security.analyze_attack_patterns")
def analyze_attack_patterns(self):
    async def _analyze():
        async with AsyncSessionLocal() as db:
            results = []
            
            attack_types = await db.execute(
                select(AttackLog.attack_type, func.count(AttackLog.id))
                .where(AttackLog.timestamp >= datetime.utcnow() - timedelta(hours=24))
                .group_by(AttackLog.attack_type)
            )
            
            for attack_type, count in attack_types.all():
                severity_counts = {}
                
                severity_breakdown = await db.execute(
                    select(AttackLog.severity, func.count(AttackLog.id))
                    .where(
                        AttackLog.attack_type == attack_type,
                        AttackLog.timestamp >= datetime.utcnow() - timedelta(hours=24)
                    )
                    .group_by(AttackLog.severity)
                )
                
                for sev, sev_count in severity_breakdown.all():
                    severity_counts[sev] = sev_count
                
                results.append({
                    "attack_type": attack_type,
                    "total_count": count,
                    "severity_breakdown": severity_counts
                })
            
            return {
                "analysis_period": "24h",
                "patterns": results,
                "timestamp": datetime.utcnow().isoformat()
            }
    
    import asyncio
    return asyncio.run(_analyze())


@shared_task(bind=True, name="app.tasks.security.auto_block_threshold")
def auto_block_threshold(self, threshold: int = 10):
    async def _process():
        async with AsyncSessionLocal() as db:
            threshold_time = datetime.utcnow() - timedelta(minutes=15)
            
            high_frequency_ips = await db.execute(
                select(AttackLog.ip_address, func.count(AttackLog.id))
                .where(
                    AttackLog.timestamp >= threshold_time,
                    AttackLog.severity.in_(['critical', 'high'])
                )
                .group_by(AttackLog.ip_address)
                .having(func.count(AttackLog.id) >= threshold)
            )
            
            blocked_count = 0
            
            for ip, count in high_frequency_ips.all():
                existing = await db.execute(
                    select(BlockedIP).where(BlockedIP.ip_address == ip)
                )
                
                if not existing.scalar_one_or_none():
                    blocked_ip = BlockedIP(
                        ip_address=ip,
                        reason=f"Auto-blocked: {count} high-severity attacks in 15 minutes",
                        is_permanent=False,
                        expires_at=datetime.utcnow() + timedelta(hours=1)
                    )
                    db.add(blocked_ip)
                    blocked_count += 1
                    logger.warning(f"Auto-blocked {ip} for {count} attacks")
            
            await db.commit()
            
            return {
                "threshold": threshold,
                "time_window": "15 minutes",
                "blocked_count": blocked_count,
                "timestamp": datetime.utcnow().isoformat()
            }
    
    import asyncio
    return asyncio.run(_process())


@shared_task(bind=True, name="app.tasks.security.manual_ip_block")
def manual_ip_block(self, ip_address: str, reason: str, permanent: bool = False, expires_hours: int = None):
    async def _block():
        async with AsyncSessionLocal() as db:
            existing = await db.execute(
                select(BlockedIP).where(BlockedIP.ip_address == ip_address)
            )
            
            if existing.scalar_one_or_none():
                return {"success": False, "error": "IP already blocked"}
            
            expires_at = None
            if not permanent and expires_hours:
                expires_at = datetime.utcnow() + timedelta(hours=expires_hours)
            
            blocked_ip = BlockedIP(
                ip_address=ip_address,
                reason=reason,
                is_permanent=permanent,
                expires_at=expires_at
            )
            
            db.add(blocked_ip)
            await db.commit()
            
            return {
                "success": True,
                "ip_address": ip_address,
                "permanent": permanent,
                "expires_at": expires_at.isoformat() if expires_at else None
            }
    
    import asyncio
    return asyncio.run(_block())