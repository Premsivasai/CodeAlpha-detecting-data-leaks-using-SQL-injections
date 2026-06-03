from celery_config import celery_app
from app.config import settings
import logging
from datetime import datetime, timedelta
from typing import Optional
import asyncio

logger = logging.getLogger(__name__)


@celery_app.task(name="billing.sync_tenant_usage", bind=True)
def sync_tenant_usage(self):
    if not settings.STRIPE_ENABLED:
        return {"status": "skipped", "reason": "Stripe not enabled"}
    
    logger.info("Syncing tenant usage data")
    
    try:
        from app.database import AsyncSessionLocal
        from sqlalchemy import select
        from app.models import Tenant, TenantBilling, AttackLog, User
        
        async def _sync():
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(Tenant).where(Tenant.is_active == True)
                )
                tenants = result.scalars().all()
                
                synced = 0
                for tenant in tenants:
                    api_calls = await count_tenant_api_calls(db, tenant.id)
                    storage_mb = await count_tenant_storage(db, tenant.id)
                    users_count = await count_tenant_users(db, tenant.id)
                    
                    billing_result = await db.execute(
                        select(TenantBilling).where(TenantBilling.tenant_id == tenant.id)
                    )
                    billing = billing_result.scalar_one_or_none()
                    
                    if billing:
                        billing.api_calls_used = api_calls
                        billing.storage_used_mb = storage_mb
                        
                        if billing.billing_cycle_end and datetime.utcnow() > billing.billing_cycle_end:
                            await reset_billing_cycle(db, billing)
                        
                        await db.commit()
                        synced += 1
                
                return {"synced": synced, "timestamp": datetime.utcnow().isoformat()}
        
        return asyncio.run(_sync())
    except Exception as e:
        logger.error(f"Tenant usage sync failed: {e}")
        return {"error": str(e)}


async def count_tenant_api_calls(db, tenant_id: int) -> int:
    from sqlalchemy import select, func
    from app.models import AttackLog
    
    result = await db.execute(
        select(func.count(AttackLog.id))
        .where(AttackLog.tenant_id == tenant_id)
        .where(AttackLog.timestamp >= datetime.utcnow() - timedelta(days=30))
    )
    return result.scalar() or 0


async def count_tenant_storage(db, tenant_id: int) -> int:
    from sqlalchemy import select, func
    from app.models import AttackLog
    
    result = await db.execute(
        select(func.sum(func.length(AttackLog.payload)))
        .where(AttackLog.tenant_id == tenant_id)
    )
    bytes_used = result.scalar() or 0
    return int(bytes_used / (1024 * 1024))


async def count_tenant_users(db, tenant_id: int) -> int:
    from sqlalchemy import select, func
    from app.models import User
    
    result = await db.execute(
        select(func.count(User.id)).where(User.tenant_id == tenant_id)
    )
    return result.scalar() or 0


async def reset_billing_cycle(db, billing: TenantBilling):
    billing.billing_cycle_start = billing.billing_cycle_end
    billing.billing_cycle_end = billing.billing_cycle_end + timedelta(days=settings.BILLING_CYCLE_DAYS)
    billing.api_calls_used = 0
    billing.storage_used_mb = 0


@celery_app.task(name="billing.check_quota_exceeded", bind=True)
def check_quota_exceeded(self, tenant_id: int):
    logger.info(f"Checking quota for tenant {tenant_id}")
    
    try:
        from app.database import AsyncSessionLocal
        from sqlalchemy import select
        from app.models import TenantBilling
        
        async def _check():
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(TenantBilling).where(TenantBilling.tenant_id == tenant_id)
                )
                billing = result.scalar_one_or_none()
                
                if not billing:
                    return {"within_quota": True}
                
                api_exceeded = billing.api_calls_used >= billing.api_calls_limit
                storage_exceeded = billing.storage_used_mb >= billing.storage_limit_mb
                
                return {
                    "within_quota": not (api_exceeded or storage_exceeded),
                    "api_calls": {
                        "used": billing.api_calls_used,
                        "limit": billing.api_calls_limit,
                        "exceeded": api_exceeded
                    },
                    "storage": {
                        "used_mb": billing.storage_used_mb,
                        "limit_mb": billing.storage_limit_mb,
                        "exceeded": storage_exceeded
                    }
                }
        
        return asyncio.run(_check())
    except Exception as e:
        logger.error(f"Quota check failed: {e}")
        return {"error": str(e), "within_quota": True}


@celery_app.task(name="billing.create_stripe_subscription", bind=True)
def create_stripe_subscription(self, tenant_id: int, plan: str):
    if not settings.STRIPE_ENABLED or not settings.STRIPE_API_KEY:
        return {"status": "skipped", "reason": "Stripe not configured"}
    
    try:
        import stripe
        stripe.api_key = settings.STRIPE_API_KEY
        
        from app.database import AsyncSessionLocal
        from sqlalchemy import select
        from app.models import TenantBilling
        
        async def _create():
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(TenantBilling).where(TenantBilling.tenant_id == tenant_id)
                )
                billing = result.scalar_one_or_none()
                
                if not billing or not billing.stripe_customer_id:
                    return {"error": "No customer ID"}
                
                price_id = get_plan_price_id(plan)
                subscription = stripe.Subscription.create(
                    customer=billing.stripe_customer_id,
                    items=[{"price": price_id}],
                    metadata={"tenant_id": str(tenant_id)}
                )
                
                billing.stripe_subscription_id = subscription.id
                billing.plan = plan
                billing.api_calls_limit = get_plan_quota(plan)["api_calls"]
                billing.storage_limit_mb = get_plan_quota(plan)["storage_mb"]
                
                await db.commit()
                
                return {
                    "subscription_id": subscription.id,
                    "plan": plan,
                    "status": subscription.status
                }
        
        return asyncio.run(_create())
    except Exception as e:
        logger.error(f"Stripe subscription creation failed: {e}")
        return {"error": str(e)}


@celery_app.task(name="billing.process_payment", bind=True)
def process_payment(self, tenant_id: int, amount: int, currency: str = "usd"):
    if not settings.STRIPE_ENABLED:
        return {"status": "skipped"}
    
    logger.info(f"Processing payment for tenant {tenant_id}: {amount} {currency}")
    
    return {
        "status": "pending",
        "tenant_id": tenant_id,
        "amount": amount,
        "currency": currency
    }


@celery_app.task(name="billing.send_usage_alert", bind=True)
def send_usage_alert(self, tenant_id: int, usage_percent: float):
    if usage_percent < 80:
        return {"status": "skipped", "reason": "Usage below threshold"}
    
    logger.info(f"Sending usage alert for tenant {tenant_id}: {usage_percent}%")
    
    try:
        from app.database import AsyncSessionLocal
        from sqlalchemy import select
        from app.models import Tenant, User
        
        async def _send():
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(User).where(User.tenant_id == tenant_id, User.role == "admin")
                )
                admins = result.scalars().all()
                
                from app.logs import alert_service
                for admin in admins:
                    await alert_service.create_alert(
                        db,
                        alert_type="billing",
                        severity="warning" if usage_percent < 95 else "critical",
                        title=f"Usage Alert: {usage_percent:.1f}% of quota used",
                        message=f"Your organization has used {usage_percent:.1f}% of its monthly quota.",
                        user_id=admin.id
                    )
                
                return {"alerted": len(admins)}
        
        return asyncio.run(_send())
    except Exception as e:
        logger.error(f"Usage alert failed: {e}")
        return {"error": str(e)}


def get_plan_price_id(plan: str) -> str:
    prices = {
        "free": "price_free",
        "starter": "price_starter",
        "professional": "price_professional",
        "enterprise": "price_enterprise"
    }
    return prices.get(plan, prices["free"])


def get_plan_quota(plan: str) -> dict:
    quotas = {
        "free": {"api_calls": 10000, "storage_mb": 1000, "users": 10},
        "starter": {"api_calls": 100000, "storage_mb": 10000, "users": 50},
        "professional": {"api_calls": 500000, "storage_mb": 50000, "users": 200},
        "enterprise": {"api_calls": -1, "storage_mb": -1, "users": -1}
    }
    return quotas.get(plan, quotas["free"])