import re
import hashlib
from typing import Optional
from urllib.parse import urlparse, urlunparse


def mask_connection_string(connection_string: str, show_host: bool = True) -> str:
    if not connection_string:
        return "***"
    
    try:
        parsed = urlparse(connection_string)
        
        if not parsed.scheme:
            return connection_string
        
        netloc = parsed.netloc
        
        if '@' in netloc:
            user_pass, host_port = netloc.split('@', 1)
            
            if ':' in user_pass:
                user, pass_part = user_pass.split(':', 1)
                masked_user = f"{user}:{'*' * min(len(pass_part), 8)}"
            else:
                masked_user = f"{user_pass}:***"
            
            if show_host:
                netloc = f"{masked_user}@{host_port}"
            else:
                host_part = host_port.split(':')[0] if ':' in host_port else host_port
                netloc = f"{masked_user}@{'*' * len(host_part)}:{parsed.port or 5432}"
        else:
            if show_host:
                pass
            else:
                if ':' in netloc:
                    host, port = netloc.split(':', 1)
                    netloc = f"{'*' * len(host)}:{port}"
                else:
                    netloc = f"{'*' * len(netloc)}"
        
        masked = urlunparse((
            parsed.scheme,
            netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
        
        return masked
        
    except Exception:
        if len(connection_string) > 20:
            return f"{connection_string[:10]}...{connection_string[-10:]}"
        return "***"


def mask_sensitive_data(data: str, show_last: int = 4) -> str:
    if not data or len(data) <= show_last:
        return "***"
    return f"{'*' * (len(data) - show_last)}{data[-show_last:]}"


def get_connection_hash(connection_string: str) -> str:
    return hashlib.sha256(connection_string.encode()).hexdigest()[:16]


def validate_connection_string(connection_string: str, allowed_schemes: list = None) -> bool:
    if allowed_schemes is None:
        allowed_schemes = ['postgresql', 'mysql', 'mongodb', 'redis']
    
    try:
        parsed = urlparse(connection_string)
        return parsed.scheme.lower() in allowed_schemes
    except Exception:
        return False


def parse_postgres_url(url: str) -> dict:
    try:
        parsed = urlparse(url)
        
        return {
            'host': parsed.hostname or 'localhost',
            'port': parsed.port or 5432,
            'database': parsed.path.lstrip('/') if parsed.path else '',
            'user': parsed.username or 'postgres',
            'scheme': parsed.scheme
        }
    except Exception:
        return {}


class RequestTracer:
    def __init__(self):
        self.traces = {}
    
    def start_trace(self, request_id: str, operation: str):
        import time
        if request_id not in self.traces:
            self.traces[request_id] = []
        
        self.traces[request_id].append({
            'operation': operation,
            'start_time': time.time(),
            'end_time': None,
            'duration': None
        })
    
    def end_trace(self, request_id: str, operation: str):
        import time
        if request_id in self.traces:
            for trace in self.traces[request_id]:
                if trace['operation'] == operation and trace['end_time'] is None:
                    trace['end_time'] = time.time()
                    trace['duration'] = trace['end_time'] - trace['start_time']
                    break
    
    def get_trace(self, request_id: str) -> list:
        return self.traces.get(request_id, [])
    
    def clear_old_traces(self, max_age_seconds: int = 3600):
        import time
        current_time = time.time()
        old_keys = [
            k for k, v in self.traces.items()
            if all(t.get('end_time', 0) < current_time - max_age_seconds for t in v)
        ]
        for k in old_keys:
            del self.traces[k]


request_tracer = RequestTracer()