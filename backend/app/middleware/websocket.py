import uuid
import time
from typing import Dict, Optional
from starlette.websockets import WebSocketState
from fastapi import WebSocket, WebSocketDisconnect
import logging

logger = logging.getLogger(__name__)


class WebSocketConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.connection_metadata: Dict[str, dict] = {}
        self._max_connections = 1000
    
    async def connect(self, websocket: WebSocket, client_ip: str, user_id: Optional[int] = None) -> bool:
        if len(self.active_connections) >= self._max_connections:
            logger.warning(f"Max WebSocket connections reached, rejecting from {client_ip}")
            await websocket.close(code=1013, reason="Server full")
            return False
        
        connection_id = str(uuid.uuid4())
        
        self.active_connections[connection_id] = websocket
        self.connection_metadata[connection_id] = {
            "client_ip": client_ip,
            "user_id": user_id,
            "connected_at": time.time(),
            "last_ping": time.time(),
            "messages_sent": 0,
            "messages_received": 0
        }
        
        logger.info(f"WebSocket connected: {connection_id} from {client_ip}, user_id={user_id}")
        return True
    
    async def disconnect(self, connection_id: str):
        if connection_id in self.active_connections:
            try:
                await self.active_connections[connection_id].close()
            except Exception:
                pass
            
            del self.active_connections[connection_id]
            
            if connection_id in self.connection_metadata:
                metadata = self.connection_metadata[connection_id]
                duration = time.time() - metadata.get("connected_at", 0)
                logger.info(f"WebSocket disconnected: {connection_id}, duration={duration:.2f}s")
                del self.connection_metadata[connection_id]
    
    async def send_personal_message(self, message: dict, connection_id: str) -> bool:
        if connection_id not in self.active_connections:
            return False
        
        try:
            websocket = self.active_connections[connection_id]
            if websocket.client_state == WebSocketState.CONNECTED:
                await websocket.send_json(message)
                self.connection_metadata[connection_id]["messages_sent"] += 1
                return True
        except Exception as e:
            logger.error(f"Error sending message to {connection_id}: {e}")
        
        return False
    
    async def broadcast(self, message: dict):
        disconnected = []
        
        for connection_id, websocket in self.active_connections.items():
            try:
                if websocket.client_state == WebSocketState.CONNECTED:
                    await websocket.send_json(message)
                    self.connection_metadata[connection_id]["messages_sent"] += 1
                else:
                    disconnected.append(connection_id)
            except Exception as e:
                logger.error(f"Error broadcasting to {connection_id}: {e}")
                disconnected.append(connection_id)
        
        for connection_id in disconnected:
            await self.disconnect(connection_id)
    
    def get_connection_info(self, connection_id: str) -> Optional[dict]:
        return self.connection_metadata.get(connection_id)
    
    def get_all_connections(self) -> list:
        return [
            {"connection_id": cid, **meta}
            for cid, meta in self.connection_metadata.items()
        ]
    
    def get_user_connections(self, user_id: int) -> list:
        return [
            {"connection_id": cid, **meta}
            for cid, meta in self.connection_metadata.items()
            if meta.get("user_id") == user_id
        ]
    
    async def disconnect_user(self, user_id: int):
        connections_to_disconnect = [
            cid for cid, meta in self.connection_metadata.items()
            if meta.get("user_id") == user_id
        ]
        
        for connection_id in connections_to_disconnect:
            await self.disconnect(connection_id)
        
        return len(connections_to_disconnect)
    
    def get_stats(self) -> dict:
        total_connections = len(self.active_connections)
        authenticated = sum(1 for m in self.connection_metadata.values() if m.get("user_id"))
        
        return {
            "total_connections": total_connections,
            "authenticated_connections": authenticated,
            "anonymous_connections": total_connections - authenticated,
            "max_connections": self._max_connections
        }


ws_manager = WebSocketConnectionManager()


class WebSocketSecurityMiddleware:
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "websocket":
            await self.app(scope, receive, send)
            return
        
        scope["state"]["ws_connection_id"] = None
        
        await self.app(scope, receive, send)


class WebSocketRateLimiter:
    def __init__(self, messages_per_minute: int = 60):
        self.messages_per_minute = messages_per_minute
        self.user_messages: Dict[str, list] = {}
    
    async def check_rate_limit(self, connection_id: str) -> bool:
        current_time = time.time()
        
        if connection_id not in self.user_messages:
            self.user_messages[connection_id] = []
        
        self.user_messages[connection_id] = [
            t for t in self.user_messages[connection_id]
            if current_time - t < 60
        ]
        
        if len(self.user_messages[connection_id]) >= self.messages_per_minute:
            return False
        
        self.user_messages[connection_id].append(current_time)
        return True
    
    def cleanup(self):
        current_time = time.time()
        for connection_id in list(self.user_messages.keys()):
            self.user_messages[connection_id] = [
                t for t in self.user_messages[connection_id]
                if current_time - t < 60
            ]
            if not self.user_messages[connection_id]:
                del self.user_messages[connection_id]


ws_rate_limiter = WebSocketRateLimiter()


async def handle_websocket_connection(websocket: WebSocket, user_id: Optional[int] = None):
    from app.logs import ip_blocker
    from app.database import AsyncSessionLocal
    
    client_host = websocket.client.host if websocket.client else "unknown"
    
    async with AsyncSessionLocal() as db:
        is_blocked = await ip_blocker.is_blocked(db, client_host)
        
        if is_blocked:
            await websocket.close(code=4003, reason="IP blocked")
            logger.warning(f"Blocked WebSocket connection from {client_host}")
            return None
    
    connected = await ws_manager.connect(websocket, client_host, user_id)
    
    if not connected:
        return None
    
    await websocket.accept()
    
    connection_id = None
    for cid, ws in ws_manager.active_connections.items():
        if ws is websocket:
            connection_id = cid
            break
    
    return connection_id