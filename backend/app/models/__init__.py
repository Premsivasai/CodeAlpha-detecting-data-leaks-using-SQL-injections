from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, Float, ForeignKey, JSON, Enum as SQLEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
import enum


Base = declarative_base()


class UserRole(enum.Enum):
    USER = "user"
    MODERATOR = "moderator"
    SECURITY_ANALYST = "security_analyst"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)
    username = Column(String(50), index=True, nullable=False)
    email = Column(String(255), index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    phone_number = Column(String(30), nullable=True)
    role = Column(SQLEnum(UserRole), default=UserRole.USER)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(255), nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    last_login = Column(DateTime, nullable=True)
    ip_addresses = Column(JSON, default=list)
    settings = Column(JSON, default=dict)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant", back_populates="users")
    tokens = relationship("RefreshToken", back_populates="user")
    sessions = relationship("ActiveSession", back_populates="user")
    capabilities = relationship("CapabilityToken", back_populates="user")
    attack_logs = relationship("AttackLog", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(500), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=func.now())
    revoked = Column(Boolean, default=False)

    # backref relationship already defined in User.tokens

    user = relationship("User", back_populates="tokens")


class ActiveSession(Base):
    __tablename__ = "active_sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(255), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    ip_address = Column(String(45), nullable=False)
    user_agent = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)

    user = relationship("User", back_populates="sessions")


class CapabilityToken(Base):
    __tablename__ = "capability_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(500), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    permissions = Column(JSON, nullable=False)
    resources = Column(JSON, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=func.now())
    is_active = Column(Boolean, default=True)

    user = relationship("User", back_populates="capabilities")


class AttackLog(Base):
    __tablename__ = "attack_logs"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    attack_type = Column(String(100), nullable=False)
    payload = Column(Text, nullable=False)
    target = Column(String(255), nullable=True)
    severity = Column(String(20), nullable=False)
    detection_method = Column(String(50), nullable=False)
    blocked = Column(Boolean, default=True)
    timestamp = Column(DateTime, default=func.now(), index=True)
    meta = Column(JSON, nullable=True)

    user = relationship("User", back_populates="attack_logs")
    tenant = relationship("Tenant", back_populates="attack_logs")


class QueryLog(Base):
    __tablename__ = "query_logs"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)
    connection_id = Column(Integer, ForeignKey("database_connections.id"), nullable=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    query = Column(Text, nullable=False)
    parameters = Column(JSON, nullable=True)
    execution_time = Column(Float, nullable=True)
    timestamp = Column(DateTime, default=func.now())
    ip_address = Column(String(45), nullable=True)
    blocked = Column(Boolean, default=False)
    block_reason = Column(String(255), nullable=True)


class EncryptionLog(Base):
    __tablename__ = "encryption_logs"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)
    operation_type = Column(String(50), nullable=False)
    data_type = Column(String(50), nullable=True)
    success = Column(Boolean, default=True)
    timestamp = Column(DateTime, default=func.now())
    meta = Column(JSON, nullable=True)


class FailedLoginAttempt(Base):
    __tablename__ = "failed_login_attempts"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), nullable=False)
    ip_address = Column(String(45), nullable=False)
    user_agent = Column(String(500), nullable=True)
    timestamp = Column(DateTime, default=func.now())
    attempts = Column(Integer, default=1)


class AIDetectionResult(Base):
    __tablename__ = "ai_detection_results"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)
    query = Column(Text, nullable=False)
    threat_score = Column(Float, nullable=False)
    prediction = Column(String(20), nullable=False)
    confidence = Column(Float, nullable=False)
    model_version = Column(String(50), nullable=True)
    features = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=func.now())

    tenant = relationship("Tenant", back_populates="ai_detection_results")


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)
    reason = Column(String(255), nullable=True)
    blocked_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=True)
    is_permanent = Column(Boolean, default=False)


class SystemAlert(Base):
    __tablename__ = "system_alerts"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)
    alert_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    meta = Column(JSON, nullable=True)
    is_resolved = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.now())
    resolved_at = Column(DateTime, nullable=True)

    tenant = relationship("Tenant", back_populates="alerts")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)
    resource = Column(String(100), nullable=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)
    timestamp = Column(DateTime, default=func.now())

    user = relationship("User", back_populates="audit_logs")
    tenant = relationship("Tenant", back_populates="audit_logs")


class DatabaseConnection(Base):
    __tablename__ = "database_connections"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)
    name = Column(String(100), nullable=False)
    db_type = Column(String(20), nullable=False)
    host = Column(String(255), nullable=False)
    port = Column(Integer, nullable=False)
    database_name = Column(String(255), nullable=True)
    username = Column(String(255), nullable=True)
    password_encrypted = Column(Text, nullable=True)
    ssl_enabled = Column(Boolean, default=True)
    is_active = Column(Boolean, default=True)
    status = Column(String(50), default="unknown")
    last_tested_at = Column(DateTime, nullable=True)
    last_test_ok = Column(Boolean, nullable=True)
    connection_metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant")


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    notification_type = Column(String(50), default="info")
    is_read = Column(Boolean, default=False)
    delivery_status = Column(String(50), default="pending")
    delivery_target = Column(String(255), nullable=True)
    delivery_attempts = Column(Integer, default=0)
    last_delivery_error = Column(Text, nullable=True)
    delivered_at = Column(DateTime, nullable=True)
    next_retry_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())

    user = relationship("User")


class NotificationDeliveryAttempt(Base):
    __tablename__ = "notification_delivery_attempts"

    id = Column(Integer, primary_key=True, index=True)
    notification_id = Column(Integer, ForeignKey("notifications.id"), nullable=False)
    target = Column(String(255), nullable=True)
    attempt_number = Column(Integer, nullable=False, default=1)
    status = Column(String(50), nullable=False, default="pending")
    error_message = Column(Text, nullable=True)
    response_code = Column(Integer, nullable=True)
    next_attempt_at = Column(DateTime, nullable=True)
    delivered_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())

    notification = relationship("Notification")


class SecurityMetric(Base):
    __tablename__ = "security_metrics"

    id = Column(Integer, primary_key=True, index=True)
    metric_type = Column(String(50), nullable=False)
    value = Column(Float, nullable=False)
    timestamp = Column(DateTime, default=func.now())
    meta = Column(JSON, nullable=True)


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False)
    permissions = Column(JSON, default=list)
    created_at = Column(DateTime, default=func.now())


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(String(255), nullable=True)
    resource = Column(String(50), nullable=False)
    action = Column(String(50), nullable=False)
    created_at = Column(DateTime, default=func.now())


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, default="medium")
    status = Column(String(50), default="open")
    meta = Column(JSON, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    reporter = relationship("User")
    tenant = relationship("Tenant", back_populates="incidents")


class GlobalConfig(Base):
    __tablename__ = "global_config"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, nullable=False, index=True)
    value = Column(JSON, nullable=False)
    encrypted = Column(Boolean, default=False)
    version = Column(Integer, default=1)
    updated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    updater = relationship("User")


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    domain = Column(String(255), nullable=True)
    encryption_key = Column(String(255), nullable=False)
    plan = Column(String(50), default="free")
    max_users = Column(Integer, default=10)
    max_ips = Column(Integer, default=100)
    max_api_calls = Column(Integer, default=10000)
    max_storage_mb = Column(Integer, default=1000)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    settings = Column(JSON, default=dict)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    users = relationship("User", back_populates="tenant")
    ip_ranges = relationship("TenantIPRange", back_populates="tenant")
    api_keys = relationship("TenantAPIKey", back_populates="tenant")
    incidents = relationship("Incident", back_populates="tenant")
    attack_logs = relationship("AttackLog", back_populates="tenant")
    alerts = relationship("SystemAlert", back_populates="tenant")
    audit_logs = relationship("AuditLog", back_populates="tenant")
    ai_detection_results = relationship("AIDetectionResult", back_populates="tenant")
    webhooks = relationship("TenantWebhook", back_populates="tenant")
    billing = relationship("TenantBilling", back_populates="tenant")


class TenantIPRange(Base):
    __tablename__ = "tenant_ip_ranges"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    cidr = Column(String(50), nullable=False)
    description = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())

    tenant = relationship("Tenant")


class TenantAPIKey(Base):
    __tablename__ = "tenant_api_keys"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    key_hash = Column(String(255), nullable=False)
    name = Column(String(100), nullable=False)
    permissions = Column(JSON, default=list)
    rate_limit = Column(Integer, default=1000)
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())

    tenant = relationship("Tenant")


class TenantWebhook(Base):
    __tablename__ = "tenant_webhooks"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    name = Column(String(100), nullable=False)
    url = Column(String(500), nullable=False)
    events = Column(JSON, default=list)
    secret = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant")


class TenantBilling(Base):
    __tablename__ = "tenant_billing"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    stripe_customer_id = Column(String(255), nullable=True)
    stripe_subscription_id = Column(String(255), nullable=True)
    plan = Column(String(50), default="free")
    billing_email = Column(String(255), nullable=True)
    api_calls_used = Column(Integer, default=0)
    api_calls_limit = Column(Integer, default=10000)
    storage_used_mb = Column(Integer, default=0)
    storage_limit_mb = Column(Integer, default=1000)
    billing_cycle_start = Column(DateTime, nullable=True)
    billing_cycle_end = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    tenant = relationship("Tenant")