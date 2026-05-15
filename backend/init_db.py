import asyncio
from sqlalchemy import select
from app.database import init_db
from app.models import Base, User, UserRole
from app.database import AsyncSessionLocal
from app.auth import get_password_hash
from app.encryption import encryption_service
from app.models import AttackLog
from datetime import datetime, timedelta
import random


async def create_admin_user():
    async with AsyncSessionLocal() as session:
        existing_usernames = set(
            (
                await session.execute(
                    select(User.username).where(User.username.in_(["admin", "testuser"]))
                )
            ).scalars().all()
        )

        users_to_create = []

        if "admin" not in existing_usernames:
            users_to_create.append(
                User(
                    username="admin",
                    email=encryption_service.encrypt("admin@secureshield.local"),
                    hashed_password=get_password_hash("Admin123!"),
                    role=UserRole.ADMIN,
                    is_active=True,
                    is_verified=True,
                )
            )

        if "testuser" not in existing_usernames:
            users_to_create.append(
                User(
                    username="testuser",
                    email=encryption_service.encrypt("user@example.com"),
                    hashed_password=get_password_hash("User123!"),
                    role=UserRole.USER,
                    is_active=True,
                    is_verified=True,
                )
            )

        if not users_to_create:
            print("Default users already exist.")
            return

        session.add_all(users_to_create)
        await session.commit()
        print("Default users created successfully!")



async def seed_sample_attacks():
    async with AsyncSessionLocal() as session:
        # check if any attack logs exist
        existing = await session.execute(select(AttackLog.id).limit(1))
        if existing.scalars().first() is not None:
            print("Attack logs already present; skipping seed.")
            return

        now = datetime.utcnow()
        sample_types = ["sql_injection", "union_injection", "time_based", "boolean_blind", "error_based"]
        severities = ["low", "medium", "high", "critical"]

        seeds = []
        # generate attacks across the last 24 hours
        for h in range(24):
            # variable number per hour
            for n in range(random.randint(0, 4)):
                ts = now - timedelta(hours=h, minutes=random.randint(0,59))
                seeds.append(
                    AttackLog(
                        user_id=None,
                        ip_address=f"192.168.1.{random.randint(2,254)}",
                        attack_type=random.choice(sample_types),
                        payload="SELECT * FROM users WHERE id = '1' --",
                        target="database",
                        severity=random.choice(severities),
                        detection_method="pattern",
                        blocked=True,
                        timestamp=ts
                    )
                )

        session.add_all(seeds)
        await session.commit()
        print(f"Seeded {len(seeds)} sample attack log entries.")


async def main():
    print("Initializing database...")
    await init_db()
    print("Database tables created!")
    
    print("Creating default users...")
    await create_admin_user()

    print("Seeding sample attack data (if needed)...")
    await seed_sample_attacks()
    
    print("Database initialization complete!")


if __name__ == "__main__":
    asyncio.run(main())