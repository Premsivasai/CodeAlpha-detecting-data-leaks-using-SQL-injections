from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
import json
import uuid
from app.encryption import encryption_service, key_manager


@dataclass
class Capability:
    user_id: int
    username: str
    permissions: List[str]
    resources: List[str]
    expires_at: datetime
    capabilities: List[str] = None
    
    def to_dict(self) -> dict:
        return {
            'user_id': self.user_id,
            'username': self.username,
            'permissions': self.permissions,
            'resources': self.resources,
            'expires_at': self.expires_at.isoformat(),
            'capabilities': self.capabilities or []
        }


class CapabilityManager:
    def __init__(self):
        self._capabilities: Dict[str, Capability] = {}
        self._user_capabilities: Dict[int, List[str]] = {}
    
    def generate_capability(
        self,
        user_id: int,
        username: str,
        permissions: List[str],
        resources: List[str],
        expiration_days: int = 7,
        capabilities: List[str] = None
    ) -> str:
        token = f"cap_{uuid.uuid4().hex}_{key_manager.get_current_key()[:8]}"
        
        expires_at = datetime.utcnow() + timedelta(days=expiration_days)
        
        capability = Capability(
            user_id=user_id,
            username=username,
            permissions=permissions,
            resources=resources,
            expires_at=expires_at,
            capabilities=capabilities
        )
        
        encrypted_token = encryption_service.encrypt(token)
        
        self._capabilities[encrypted_token] = capability
        
        if user_id not in self._user_capabilities:
            self._user_capabilities[user_id] = []
        self._user_capabilities[user_id].append(encrypted_token)
        
        return encrypted_token
    
    def validate_capability(
        self,
        token: str,
        required_permission: str = None,
        required_resource: str = None
    ) -> tuple[bool, Optional[Capability], str]:
        if token not in self._capabilities:
            for stored_token, capability in self._capabilities.items():
                try:
                    decrypted = encryption_service.decrypt(stored_token)
                    if decrypted == token:
                        token = stored_token
                        break
                except:
                    pass
        
        if token not in self._capabilities:
            return False, None, "Capability token not found"
        
        capability = self._capabilities[token]
        
        if datetime.utcnow() > capability.expires_at:
            return False, None, "Capability token has expired"
        
        if required_permission and required_permission not in capability.permissions:
            return False, None, f"Missing required permission: {required_permission}"
        
        if required_resource and required_resource not in capability.resources:
            return False, None, f"Missing required resource: {required_resource}"
        
        return True, capability, "Capability validated successfully"
    
    def revoke_capability(self, token: str) -> bool:
        if token in self._capabilities:
            capability = self._capabilities[token]
            user_id = capability.user_id
            
            del self._capabilities[token]
            
            if user_id in self._user_capabilities:
                self._user_capabilities[user_id] = [
                    t for t in self._user_capabilities[user_id] if t != token
                ]
            
            return True
        return False
    
    def revoke_all_user_capabilities(self, user_id: int) -> int:
        if user_id not in self._user_capabilities:
            return 0
        
        count = 0
        for token in self._user_capabilities[user_id]:
            if token in self._capabilities:
                del self._capabilities[token]
                count += 1
        
        del self._user_capabilities[user_id]
        return count
    
    def get_user_capabilities(self, user_id: int) -> List[Dict]:
        if user_id not in self._user_capabilities:
            return []
        
        capabilities = []
        for token in self._user_capabilities[user_id]:
            if token in self._capabilities:
                cap = self._capabilities[token]
                if datetime.utcnow() <= cap.expires_at:
                    capabilities.append({
                        'token': token[:20] + '...',
                        'permissions': cap.permissions,
                        'resources': cap.resources,
                        'expires_at': cap.expires_at.isoformat()
                    })
        
        return capabilities
    
    def cleanup_expired(self) -> int:
        expired_tokens = []
        for token, capability in self._capabilities.items():
            if datetime.utcnow() > capability.expires_at:
                expired_tokens.append(token)
        
        for token in expired_tokens:
            del self._capabilities[token]
        
        for user_id in self._user_capabilities:
            self._user_capabilities[user_id] = [
                t for t in self._user_capabilities[user_id]
                if t in self._capabilities
            ]
        
        return len(expired_tokens)


capability_manager = CapabilityManager()


class PermissionChecker:
    ROLE_PERMISSIONS = {
        'user': ['read:own', 'write:own', 'profile:read', 'profile:write'],
        'moderator': [
            'read:own', 'write:own', 'read:all', 'profile:read', 'profile:write',
            'logs:read', 'users:read', 'reports:create'
        ],
        'security_analyst': [
            'read:own', 'write:own', 'read:all', 'write:all', 'profile:read',
            'logs:read', 'logs:write', 'users:read', 'analytics:read',
            'detection:read', 'alerts:read', 'reports:create'
        ],
        'admin': [
            'read:own', 'write:own', 'read:all', 'write:all', 'delete:all',
            'profile:read', 'profile:write', 'logs:read', 'logs:write',
            'users:read', 'users:write', 'users:delete', 'analytics:read',
            'analytics:write', 'detection:read', 'detection:write',
            'alerts:read', 'alerts:write', 'reports:create', 'settings:read',
            'settings:write', 'capability:manage'
        ],
        'super_admin': [
            '*'
        ]
    }
    
    ROLE_RESOURCES = {
        'user': ['profile', 'data', 'own'],
        'moderator': ['profile', 'data', 'users', 'logs', 'reports'],
        'security_analyst': ['profile', 'data', 'users', 'logs', 'analytics', 'detection', 'alerts', 'reports'],
        'admin': ['*'],
        'super_admin': ['*']
    }
    
    @classmethod
    def get_permissions(cls, role: str) -> List[str]:
        return cls.ROLE_PERMISSIONS.get(role, ['read:own'])
    
    @classmethod
    def get_resources(cls, role: str) -> List[str]:
        return cls.ROLE_RESOURCES.get(role, ['own'])
    
    @classmethod
    def has_permission(cls, user_permissions: List[str], required: str) -> bool:
        if '*' in user_permissions:
            return True
        
        if required in user_permissions:
            return True
        
        permission_parts = required.split(':')
        if len(permission_parts) == 2:
            action, resource = permission_parts
            for perm in user_permissions:
                if perm.startswith(action):
                    if perm.endswith(':all') or resource in ['own', 'profile', 'data']:
                        return True
        
        return False
    
    @classmethod
    def has_resource_access(cls, user_resources: List[str], required: str) -> bool:
        if '*' in user_resources:
            return True
        
        return required in user_resources or required in ['own', 'profile', 'data']


permission_checker = PermissionChecker()