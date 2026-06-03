from __future__ import annotations

from typing import Dict, Optional

from app.db_connectors import MySQLConnector, MongoDBConnector
from app.db_connectors.postgres_connector import PostgresConnector


class DatabasePoolManager:
    def __init__(self):
        self._postgres_connectors: Dict[str, PostgresConnector] = {}
        self._mysql_connectors: Dict[str, MySQLConnector] = {}
        self._mongodb_connectors: Dict[str, MongoDBConnector] = {}

    def _tenant_key(self, tenant_id: int | str, name: str) -> str:
        return f"{tenant_id}:{name}"

    def register_postgres(
        self,
        name: str,
        host: str,
        port: int = 5432,
        user: str = "postgres",
        password: str = "",
        database: str = "secureshield",
        ssl: bool = False,
        tenant_id: int | str = "global",
    ) -> PostgresConnector:
        connector = PostgresConnector(host=host, port=port, user=user, password=password, database=database, ssl_enabled=ssl)
        self._postgres_connectors[self._tenant_key(tenant_id, name)] = connector
        return connector

    def register_mysql(
        self,
        name: str,
        host: str,
        port: int = 3306,
        user: str = "root",
        password: str = "",
        database: str = "",
        ssl: bool = False,
        tenant_id: int | str = "global",
    ) -> MySQLConnector:
        connector = MySQLConnector(host=host, port=port, user=user, password=password, database=database, ssl_enabled=ssl)
        self._mysql_connectors[self._tenant_key(tenant_id, name)] = connector
        return connector

    def register_mongodb(
        self,
        name: str,
        host: str,
        port: int = 27017,
        user: str = "",
        password: str = "",
        database: str = "",
        tls: bool = False,
        tenant_id: int | str = "global",
    ) -> MongoDBConnector:
        connector = MongoDBConnector(host=host, port=port, user=user, password=password, database=database, tls_enabled=tls)
        self._mongodb_connectors[self._tenant_key(tenant_id, name)] = connector
        return connector

    def get_postgres(self, name: str, tenant_id: int | str = "global") -> Optional[PostgresConnector]:
        return self._postgres_connectors.get(self._tenant_key(tenant_id, name))

    def get_mysql(self, name: str, tenant_id: int | str = "global") -> Optional[MySQLConnector]:
        return self._mysql_connectors.get(self._tenant_key(tenant_id, name))

    def get_mongodb(self, name: str, tenant_id: int | str = "global") -> Optional[MongoDBConnector]:
        return self._mongodb_connectors.get(self._tenant_key(tenant_id, name))

    async def connect_all(self):
        for connector in self._postgres_connectors.values():
            await connector.connect()
        for connector in self._mysql_connectors.values():
            await connector.connect()
        for connector in self._mongodb_connectors.values():
            await connector.connect()

    async def close_all(self):
        for connector in self._postgres_connectors.values():
            await connector.close()
        for connector in self._mysql_connectors.values():
            await connector.close()
        for connector in self._mongodb_connectors.values():
            await connector.close()


db_pool_manager = DatabasePoolManager()