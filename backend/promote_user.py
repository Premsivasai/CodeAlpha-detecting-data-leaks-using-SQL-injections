import asyncio
from sqlalchemy import text
from app.database import engine

async def promote():
    async with engine.begin() as conn:
        await conn.execute(text("UPDATE users SET role = 'ADMIN' WHERE username = 'premsiva12'"))
        print('User premsiva12 promoted to ADMIN')

asyncio.run(promote())