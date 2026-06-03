from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import sessionmaker
from app.config import settings
from app.models import Base

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

SessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("""
            ALTER TABLE notifications
            ADD COLUMN IF NOT EXISTS delivery_status VARCHAR(50) DEFAULT 'pending'
        """))
        await conn.execute(text("""
            ALTER TABLE notifications
            ADD COLUMN IF NOT EXISTS delivery_target VARCHAR(255)
        """))
        await conn.execute(text("""
            ALTER TABLE notifications
            ADD COLUMN IF NOT EXISTS delivery_attempts INTEGER DEFAULT 0
        """))
        await conn.execute(text("""
            ALTER TABLE notifications
            ADD COLUMN IF NOT EXISTS last_delivery_error TEXT
        """))
        await conn.execute(text("""
            ALTER TABLE notifications
            ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMP NULL
        """))
        await conn.execute(text("""
            ALTER TABLE notifications
            ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMP NULL
        """))
        await conn.execute(text("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS settings JSON DEFAULT '{}'::json
        """))
        await conn.execute(text("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS phone_number VARCHAR(30)
        """))
        await conn.execute(text("""
            ALTER TABLE query_logs
            ADD COLUMN IF NOT EXISTS tenant_id INTEGER
        """))
        await conn.execute(text("""
            ALTER TABLE query_logs
            ADD COLUMN IF NOT EXISTS connection_id INTEGER
        """))
        await conn.execute(text("""
            ALTER TABLE encryption_logs
            ADD COLUMN IF NOT EXISTS tenant_id INTEGER
        """))
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS database_connections (
                id SERIAL PRIMARY KEY,
                tenant_id INTEGER REFERENCES tenants(id),
                name VARCHAR(100) NOT NULL,
                db_type VARCHAR(20) NOT NULL,
                host VARCHAR(255) NOT NULL,
                port INTEGER NOT NULL,
                database_name VARCHAR(255),
                username VARCHAR(255),
                password_encrypted TEXT,
                ssl_enabled BOOLEAN DEFAULT TRUE,
                is_active BOOLEAN DEFAULT TRUE,
                status VARCHAR(50) DEFAULT 'unknown',
                last_tested_at TIMESTAMP NULL,
                last_test_ok BOOLEAN,
                connection_metadata JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_attack_logs_timestamp
            ON attack_logs (timestamp DESC)
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_database_connections_tenant
            ON database_connections (tenant_id)
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_query_logs_connection_id
            ON query_logs (connection_id)
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_attack_logs_attack_type
            ON attack_logs (attack_type)
        """))
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_attack_logs_ip_address
            ON attack_logs (ip_address)
        """))
        await conn.execute(text("""
            CREATE MATERIALIZED VIEW IF NOT EXISTS hourly_attack_stats AS
            SELECT date_trunc('hour', timestamp) AS hour,
                   attack_type,
                   severity,
                   count(*) AS cnt
            FROM attack_logs
            GROUP BY hour, attack_type, severity
        """))
        await conn.execute(text("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_hourly_attack_stats_unique
            ON hourly_attack_stats (hour, attack_type, severity)
        """))


async def drop_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)