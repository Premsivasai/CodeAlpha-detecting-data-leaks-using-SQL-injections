import json
import io
from datetime import datetime, timedelta
from celery import shared_task
from sqlalchemy import select, func
from app.database import AsyncSessionLocal
from app.models import AttackLog, SystemAlert, BlockedIP, AIDetectionResult, User


@shared_task(bind=True, name="app.tasks.reports.generate_daily_report")
def generate_daily_report(self, date: str = None):
    if date:
        target_date = datetime.fromisoformat(date).date()
    else:
        target_date = (datetime.utcnow() - timedelta(days=1)).date()
    
    async def _generate():
        async with AsyncSessionLocal() as db:
            start_time = datetime.combine(target_date, datetime.min.time())
            end_time = datetime.combine(target_date, datetime.max.time())
            
            total_attacks = await db.execute(
                select(func.count(AttackLog.id)).where(
                    AttackLog.timestamp >= start_time,
                    AttackLog.timestamp <= end_time
                )
            )
            
            attacks_by_type = await db.execute(
                select(AttackLog.attack_type, func.count(AttackLog.id))
                .where(
                    AttackLog.timestamp >= start_time,
                    AttackLog.timestamp <= end_time
                )
                .group_by(AttackLog.attack_type)
            )
            
            attacks_by_severity = await db.execute(
                select(AttackLog.severity, func.count(AttackLog.id))
                .where(
                    AttackLog.timestamp >= start_time,
                    AttackLog.timestamp <= end_time
                )
                .group_by(AttackLog.severity)
            )
            
            top_ips = await db.execute(
                select(AttackLog.ip_address, func.count(AttackLog.id))
                .where(
                    AttackLog.timestamp >= start_time,
                    AttackLog.timestamp <= end_time
                )
                .group_by(AttackLog.ip_address)
                .order_by(func.count(AttackLog.id).desc())
                .limit(10)
            )
            
            blocked_count = await db.execute(
                select(func.count(AttackLog.id)).where(
                    AttackLog.timestamp >= start_time,
                    AttackLog.timestamp <= end_time,
                    AttackLog.blocked == True
                )
            )
            
            alert_count = await db.execute(
                select(func.count(SystemAlert.id)).where(
                    SystemAlert.created_at >= start_time,
                    SystemAlert.created_at <= end_time
                )
            )
            
            report_data = {
                "date": target_date.isoformat(),
                "summary": {
                    "total_attacks": total_attacks.scalar() or 0,
                    "blocked_attacks": blocked_count.scalar() or 0,
                    "alerts_generated": alert_count.scalar() or 0
                },
                "attack_types": [
                    {"type": row[0], "count": row[1]}
                    for row in attacks_by_type.all()
                ],
                "severity_breakdown": [
                    {"severity": row[0], "count": row[1]}
                    for row in attacks_by_severity.all()
                ],
                "top_attacking_ips": [
                    {"ip": row[0], "count": row[1]}
                    for row in top_ips.all()
                ],
                "generated_at": datetime.utcnow().isoformat()
            }
            
            return report_data
    
    import asyncio
    return asyncio.run(_generate())


@shared_task(bind=True, name="app.tasks.reports.export_attack_logs")
def export_attack_logs(self, format: str = "json", start_date: str = None, end_date: str = None):
    async def _export():
        async with AsyncSessionLocal() as db:
            query = select(AttackLog).order_by(AttackLog.timestamp.desc()).limit(10000)
            
            if start_date:
                query = query.where(AttackLog.timestamp >= datetime.fromisoformat(start_date))
            if end_date:
                query = query.where(AttackLog.timestamp <= datetime.fromisoformat(end_date))
            
            result = await db.execute(query)
            logs = result.scalars().all()
            
            if format == "csv":
                import csv
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow([
                    "ID", "Timestamp", "IP Address", "Attack Type", "Severity",
                    "Blocked", "Detection Method", "Target"
                ])
                
                for log in logs:
                    writer.writerow([
                        log.id,
                        log.timestamp.isoformat() if log.timestamp else "",
                        log.ip_address,
                        log.attack_type,
                        log.severity,
                        log.blocked,
                        log.detection_method,
                        log.target or ""
                    ])
                
                return output.getvalue()
            
            else:
                return json.dumps([
                    {
                        "id": log.id,
                        "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                        "ip_address": log.ip_address,
                        "attack_type": log.attack_type,
                        "severity": log.severity,
                        "blocked": log.blocked,
                        "detection_method": log.detection_method,
                        "target": log.target,
                        "payload_preview": log.payload[:200] if log.payload else None
                    }
                    for log in logs
                ], indent=2)
    
    import asyncio
    return asyncio.run(_export())


@shared_task(bind=True, name="app.tasks.reports.generate_compliance_report")
def generate_compliance_report(self, report_type: str = "monthly"):
    async def _generate():
        async with AsyncSessionLocal() as db:
            days = 30 if report_type == "monthly" else 7
            start_date = datetime.utcnow() - timedelta(days=days)
            
            total_users = await db.execute(select(func.count(User.id)))
            active_users = await db.execute(
                select(func.count(User.id)).where(User.is_active == True)
            )
            
            total_attacks = await db.execute(
                select(func.count(AttackLog.id)).where(AttackLog.timestamp >= start_date)
            )
            
            blocked_ips = await db.execute(select(func.count(BlockedIP.id)))
            
            return {
                "report_type": report_type,
                "period_days": days,
                "generated_at": datetime.utcnow().isoformat(),
                "statistics": {
                    "total_users": total_users.scalar() or 0,
                    "active_users": active_users.scalar() or 0,
                    "total_attacks_detected": total_attacks.scalar() or 0,
                    "currently_blocked_ips": blocked_ips.scalar() or 0
                }
            }
    
    import asyncio
    return asyncio.run(_generate())