from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional
import logging
import re

import asyncpg

logger = logging.getLogger(__name__)


class PostgresConnector:
    def __init__(
        self,
        host: str = "localhost",
        port: int = 5432,
        user: str = "postgres",
        password: str = "",
        database: str = "secureshield",
        ssl_enabled: bool = False,
        min_size: int = 1,
        max_size: int = 10,
    ):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.ssl_enabled = ssl_enabled
        self.min_size = min_size
        self.max_size = max_size
        self._pool: Optional[asyncpg.Pool] = None

    async def connect(self) -> bool:
        try:
            self._pool = await asyncpg.create_pool(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                database=self.database,
                min_size=self.min_size,
                max_size=self.max_size,
                ssl="require" if self.ssl_enabled else None,
                command_timeout=30,
            )
            logger.info("Connected to PostgreSQL at %s:%s", self.host, self.port)
            return True
        except Exception as exc:
            logger.error("PostgreSQL connection failed: %s", exc)
            self._pool = None
            return False

    @asynccontextmanager
    async def get_connection(self):
        if self._pool is None:
            await self.connect()
        if self._pool is None:
            raise RuntimeError("PostgreSQL pool unavailable")

        async with self._pool.acquire() as connection:
            yield connection

    def validate_query(self, query: str) -> Dict[str, Any]:
        normalized = re.sub(r"\s+", " ", query.strip()).lower()

        if ";" in normalized.rstrip(";"):
            return {"valid": False, "error": "Multiple statements are not allowed"}

        blocked_patterns = [
            r"\bdrop\s+table\b",
            r"\btruncate\s+table\b",
            r"\balter\s+table\b",
            r"\bgrant\s+",
            r"\brevoke\s+",
            r"\bcopy\s+.*\s+from\s+stdin",
            r"\bcreate\s+database\b",
        ]
        for pattern in blocked_patterns:
            if re.search(pattern, normalized):
                return {"valid": False, "error": f"Blocked statement matched: {pattern}"}

        return {"valid": True}

    async def execute_query(
        self,
        query: str,
        params: Optional[List[Any]] = None,
        fetch_one: bool = False,
        fetch_all: bool = True,
    ) -> Optional[Any]:
        validation = self.validate_query(query)
        if not validation.get("valid"):
            return {"error": validation.get("error"), "blocked": True}

        try:
            async with self.get_connection() as connection:
                if fetch_one:
                    return await connection.fetchrow(query, *(params or []))
                if fetch_all:
                    return await connection.fetch(query, *(params or []))

                await connection.execute(query, *(params or []))
                return None
        except Exception as exc:
            logger.error("PostgreSQL query error: %s", exc)
            return {"error": str(exc), "blocked": False}

    async def test_connection(self) -> bool:
        result = await self.execute_query("SELECT 1 AS test", fetch_one=True)
        return bool(result)

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
            logger.info("PostgreSQL pool closed")

    def get_connection_string(self) -> str:
        return f"postgresql://{self.user}:****@{self.host}:{self.port}/{self.database}"