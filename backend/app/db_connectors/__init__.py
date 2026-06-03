import asyncio
from typing import Optional, Dict, List, Any
from contextlib import asynccontextmanager
import logging
from datetime import datetime
import hashlib


logger = logging.getLogger(__name__)


class MySQLConnector:
    def __init__(
        self,
        host: str = "localhost",
        port: int = 3306,
        user: str = "root",
        password: str = "",
        database: str = "",
        ssl_enabled: bool = False
    ):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.ssl_enabled = ssl_enabled
        self._pool = None
        self._connection = None
    
    async def connect(self):
        try:
            import aiomysql
            
            pool = await aiomysql.create_pool(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                db=self.database,
                minsize=5,
                maxsize=20,
                charset='utf8mb4',
                ssl={} if self.ssl_enabled else None,
                autocommit=False
            )
            self._pool = pool
            logger.info(f"Connected to MySQL at {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"MySQL connection failed: {e}")
            return False
    
    @asynccontextmanager
    async def get_connection(self):
        if not self._pool:
            await self.connect()
        
        async with self._pool.acquire() as conn:
            yield conn
    
    async def execute_query(
        self,
        query: str,
        params: tuple = None,
        fetch_one: bool = False,
        fetch_all: bool = True
    ) -> Optional[Any]:
        try:
            async with self.get_connection() as conn:
                async with conn.cursor(aiomysql.DictCursor) as cursor:
                    await cursor.execute(query, params)
                    
                    if fetch_one:
                        return await cursor.fetchone()
                    elif fetch_all:
                        return await cursor.fetchall()
                    
                    await conn.commit()
                    return None
        except Exception as e:
            logger.error(f"MySQL query error: {e}")
            return None
    
    async def execute_with_validation(
        self,
        query: str,
        params: tuple = None,
        allowed_tables: List[str] = None
    ) -> Optional[Any]:
        query_lower = query.lower()
        
        dangerous_keywords = [
            'drop', 'truncate', 'delete from',
            'alter table', 'create table',
            'grant', 'revoke'
        ]
        
        for keyword in dangerous_keywords:
            if keyword in query_lower:
                logger.warning(f"Blocked dangerous MySQL operation: {keyword}")
                return {"error": "Operation not allowed", "blocked": keyword}
        
        if allowed_tables:
            for table in allowed_tables:
                if f"from {table}" in query_lower or f"into {table}" in query_lower or f"update {table}" in query_lower:
                    break
            else:
                return {"error": "Table not in allowlist"}
        
        return await self.execute_query(query, params)
    
    async def close(self):
        if self._pool:
            self._pool.close()
            await self._pool.wait_closed()
            logger.info("MySQL connection pool closed")
    
    async def test_connection(self) -> bool:
        try:
            result = await self.execute_query("SELECT 1 as test")
            return result is not None
        except Exception:
            return False
    
    def get_connection_string(self) -> str:
        return f"mysql+aiomysql://{self.user}:****@{self.host}:{self.port}/{self.database}"


class MongoDBConnector:
    def __init__(
        self,
        host: str = "localhost",
        port: int = 27017,
        user: str = "",
        password: str = "",
        database: str = "",
        tls_enabled: bool = False
    ):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.tls_enabled = tls_enabled
        self._client = None
        self._db = None
    
    async def connect(self):
        try:
            from motor.motor_asyncio import AsyncIOMotorClient
            
            connection_string = f"mongodb://"
            if self.user and self.password:
                connection_string += f"{self.user}:{self.password}@"
            connection_string += f"{self.host}:{self.port}"
            
            if self.tls_enabled:
                connection_string += f"/?tls=true"
            
            self._client = AsyncIOMotorClient(connection_string)
            self._db = self._client[self.database]
            
            await self._client.admin.command('ping')
            logger.info(f"Connected to MongoDB at {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"MongoDB connection failed: {e}")
            return False
    
    def get_collection(self, collection_name: str):
        if not self._db:
            return None
        return self._db[collection_name]
    
    async def execute_find(
        self,
        collection: str,
        query: Dict = None,
        projection: Dict = None,
        limit: int = 100
    ) -> List[Dict]:
        try:
            coll = self.get_collection(collection)
            if not coll:
                return []
            
            cursor = coll.find(query or {}, projection).limit(limit)
            return await cursor.to_list(length=limit)
        except Exception as e:
            logger.error(f"MongoDB find error: {e}")
            return []
    
    async def execute_aggregate(
        self,
        collection: str,
        pipeline: List[Dict]
    ) -> List[Dict]:
        try:
            coll = self.get_collection(collection)
            if not coll:
                return []
            
            cursor = coll.aggregate(pipeline)
            return await cursor.to_list(length=100)
        except Exception as e:
            logger.error(f"MongoDB aggregate error: {e}")
            return []
    
    def validate_query(self, query: Dict) -> Dict:
        query_str = str(query).lower()
        
        dangerous_operators = ['$where', '$function', '$eval']
        
        for op in dangerous_operators:
            if op in query_str:
                return {
                    "valid": False,
                    "error": f"Dangerous operator not allowed: {op}"
                }
        
        return {"valid": True}
    
    async def close(self):
        if self._client:
            self._client.close()
            logger.info("MongoDB connection closed")
    
    async def test_connection(self) -> bool:
        try:
            await self._client.admin.command('ping')
            return True
        except Exception:
            return False
    
    def get_connection_string(self) -> str:
        return f"mongodb://{self.user}:****@{self.host}:{self.port}/{self.database}"


class DatabasePoolManager:
    _mysql_connectors: Dict[str, MySQLConnector] = {}
    _mongodb_connectors: Dict[str, MongoDBConnector] = {}
    
    @classmethod
    def register_mysql(
        cls,
        name: str,
        host: str,
        port: int = 3306,
        user: str = "root",
        password: str = "",
        database: str = "",
        ssl: bool = False
    ) -> MySQLConnector:
        connector = MySQLConnector(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
            ssl_enabled=ssl
        )
        cls._mysql_connectors[name] = connector
        return connector
    
    @classmethod
    def register_mongodb(
        cls,
        name: str,
        host: str,
        port: int = 27017,
        user: str = "",
        password: str = "",
        database: str = "",
        tls: bool = False
    ) -> MongoDBConnector:
        connector = MongoDBConnector(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
            tls_enabled=tls
        )
        cls._mongodb_connectors[name] = connector
        return connector
    
    @classmethod
    def get_mysql(cls, name: str) -> Optional[MySQLConnector]:
        return cls._mysql_connectors.get(name)
    
    @classmethod
    def get_mongodb(cls, name: str) -> Optional[MongoDBConnector]:
        return cls._mongodb_connectors.get(name)
    
    @classmethod
    async def connect_all(cls):
        for name, connector in cls._mysql_connectors.items():
            await connector.connect()
        
        for name, connector in cls._mongodb_connectors.items():
            await connector.connect()
    
    @classmethod
    async def close_all(cls):
        for name, connector in cls._mysql_connectors.items():
            await connector.close()
        
        for name, connector in cls._mongodb_connectors.items():
            await connector.close()


db_pool_manager = DatabasePoolManager()