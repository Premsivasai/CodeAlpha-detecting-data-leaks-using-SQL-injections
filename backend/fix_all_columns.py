import asyncio
from sqlalchemy import text
from app.database import engine

async def add_missing_columns():
    async with engine.begin() as conn:
        # Check and add tenant_id to tables that need it
        tables_with_tenant = ['users', 'attack_logs', 'audit_logs', 'incidents', 'alerts']

        for table in tables_with_tenant:
            result = await conn.execute(text(f"""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = '{table}' AND column_name = 'tenant_id'
            """))
            if not result.fetchone():
                await conn.execute(text(f'ALTER TABLE {table} ADD COLUMN tenant_id INTEGER'))
                print(f'Added tenant_id to {table}')
            else:
                print(f'tenant_id already exists in {table}')

        # Check tenants table
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

        print('All schema fixes complete!')

asyncio.run(add_missing_columns())