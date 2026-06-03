from datetime import datetime
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_
from app.models import Tenant, TenantIPRange, TenantAPIKey, User
import hashlib
import secrets


class TenantService:
    @staticmethod
    async def create_tenant(
        db: AsyncSession,
        name: str,
        slug: str,
        domain: Optional[str] = None,
        plan: str = "free"
    ) -> Tenant:
        encryption_key = secrets.token_hex(32)
        
        tenant = Tenant(
            name=name,
            slug=slug,
            domain=domain,
            encryption_key=encryption_key,
            plan=plan,
            max_users=10,
            max_ips=100,
            is_active=True,
            settings={
                "allow_mfa": True,
                "allow_api_keys": True,
                "log_retention_days": 90,
                "ip_whitelist_enabled": False,
            }
        )
        
        db.add(tenant)
        await db.commit()
        await db.refresh(tenant)
        
        return tenant

    @staticmethod
    async def get_tenant_by_id(db: AsyncSession, tenant_id: int) -> Optional[Tenant]:
        result = await db.execute(
            select(Tenant).where(Tenant.id == tenant_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def get_tenant_by_slug(db: AsyncSession, slug: str) -> Optional[Tenant]:
        result = await db.execute(
            select(Tenant).where(Tenant.slug == slug)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def assign_user_to_tenant(
        db: AsyncSession,
        user_id: int,
        tenant_id: int
    ) -> User:
        result = await db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if user:
            user.tenant_id = tenant_id
            await db.commit()
            await db.refresh(user)
        
        return user

    @staticmethod
    async def create_api_key(
        db: AsyncSession,
        tenant_id: int,
        name: str,
        permissions: List[str] = None,
        rate_limit: int = 1000
    ) -> str:
        api_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        tenant_key = TenantAPIKey(
            tenant_id=tenant_id,
            key_hash=key_hash,
            name=name,
            permissions=permissions or ["read"],
            rate_limit=rate_limit,
            is_active=True
        )
        
        db.add(tenant_key)
        await db.commit()
        
        return api_key

    @staticmethod
    async def validate_api_key(
        db: AsyncSession,
        api_key: str,
        tenant_id: int
    ) -> Optional[TenantAPIKey]:
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        result = await db.execute(
            select(TenantAPIKey).where(
                and_(
                    TenantAPIKey.tenant_id == tenant_id,
                    TenantAPIKey.key_hash == key_hash,
                    TenantAPIKey.is_active == True
                )
            )
        )
        key_obj = result.scalar_one_or_none()
        
        if key_obj:
            if key_obj.expires_at and key_obj.expires_at < datetime.utcnow():
                return None
            
            key_obj.last_used_at = datetime.utcnow()
            await db.commit()
        
        return key_obj

    @staticmethod
    async def add_ip_range(
        db: AsyncSession,
        tenant_id: int,
        cidr: str,
        description: str = None
    ) -> TenantIPRange:
        ip_range = TenantIPRange(
            tenant_id=tenant_id,
            cidr=cidr,
            description=description,
            is_active=True
        )
        
        db.add(ip_range)
        await db.commit()
        await db.refresh(ip_range)
        
        return ip_range

    @staticmethod
    async def is_ip_allowed(
        db: AsyncSession,
        tenant_id: int,
        ip_address: str
    ) -> bool:
        tenant = await TenantService.get_tenant_by_id(db, tenant_id)
        if not tenant:
            return True
        
        settings = tenant.settings or {}
        if not settings.get("ip_whitelist_enabled", False):
            return True
        
        result = await db.execute(
            select(TenantIPRange).where(
                and_(
                    TenantIPRange.tenant_id == tenant_id,
                    TenantIPRange.is_active == True
                )
            )
        )
        ip_ranges = result.scalars().all()
        
        for ip_range in ip_ranges:
            if TenantService._ip_in_cidr(ip_address, ip_range.cidr):
                return True
        
        return False

    @staticmethod
    def _ip_in_cidr(ip: str, cidr: str) -> bool:
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)
        except Exception:
            return False


class TenantContext:
    def __init__(self, tenant_id: int, tenant_slug: str, encryption_key: str):
        self.tenant_id = tenant_id
        self.tenant_slug = tenant_slug
        self.encryption_key = encryption_key
    
    def get_encryption_key(self) -> str:
        return self.encryption_key


tenant_service = TenantService()