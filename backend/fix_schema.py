import asyncio
from sqlalchemy import text
from app.database import engine

async def add_column():
    async with engine.begin() as conn:
        result = await conn.execute(text("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'users' AND column_name = 'tenant_id'
        """))
        if not result.fetchone():
            await conn.execute(text('ALTER TABLE users ADD COLUMN tenant_id INTEGER'))
            print('Added tenant_id column to users table')
        else:
            print('tenant_id column already exists')

        # Also check tenants table exists
        result = await conn.execute(text("""
            SELECT table_name FROM information_schema.tables
            WHERE table_name = 'tenants'
        """))
        if not result.fetchone():
            await conn.execute(text('''
                CREATE TABLE IF NOT EXISTS tenants (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    slug VARCHAR(100) UNIQUE NOT NULL,
                    plan VARCHAR(50) DEFAULT 'free',
                    created_at TIMESTAMP DEFAULT NOW()
                )
            '''))
            print('Created tenants table')
        else:
            print('tenants table already exists')

        result = await conn.execute(text("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'attack_logs' AND column_name = 'tenant_id'
        """))
        if not result.fetchone():
            await conn.execute(text('ALTER TABLE attack_logs ADD COLUMN tenant_id INTEGER'))
            print('Added tenant_id column to attack_logs table')
        else:
            print('tenant_id column already exists in attack_logs')

        tables_needing_tenant = ['system_alerts', 'security_metrics', 'query_logs', 'blocked_ips', 'ai_detection_results', 'incidents', 'audit_logs']
        for table in tables_needing_tenant:
            result = await conn.execute(text(f"""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = '{table}' AND column_name = 'tenant_id'
            """))
            if not result.fetchone():
                await conn.execute(text(f'ALTER TABLE {table} ADD COLUMN tenant_id INTEGER'))
                print(f'Added tenant_id column to {table} table')
            else:
                print(f'tenant_id column already exists in {table}')

asyncio.run(add_column())