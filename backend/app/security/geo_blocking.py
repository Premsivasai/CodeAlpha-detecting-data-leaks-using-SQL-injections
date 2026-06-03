import ipaddress
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging


logger = logging.getLogger(__name__)


@dataclass
class GeoLocation:
    country: str
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    isp: Optional[str] = None
    asn: Optional[str] = None


@dataclass
class GeoBlockingRule:
    rule_id: str
    action: str
    country_codes: List[str]
    is_whitelist: bool
    description: str
    created_at: datetime


class GeoBlockingService:
    def __init__(self):
        self._rules: List[GeoBlockingRule] = []
        self._country_names: Dict[str, str] = {
            'US': 'United States', 'CN': 'China', 'RU': 'Russia',
            'KP': 'North Korea', 'IR': 'Iran', 'SY': 'Syria',
            'BY': 'Belarus', 'VN': 'Vietnam', 'IN': 'India',
            'BR': 'Brazil', 'RO': 'Romania', 'UA': 'Ukraine',
            'DE': 'Germany', 'FR': 'France', 'GB': 'United Kingdom',
            'JP': 'Japan', 'KR': 'South Korea', 'IN': 'Indonesia',
            'PK': 'Pakistan', 'TR': 'Turkey', 'TH': 'Thailand'
        }
        self._init_default_rules()
    
    def _init_default_rules(self):
        self._rules = [
            GeoBlockingRule(
                rule_id="block_high_risk",
                action="block",
                country_codes=["KP", "IR", "SY"],
                is_whitelist=False,
                description="Block traffic from high-risk countries"
            )
        ]
    
    def _get_country_from_ip(self, ip_address: str) -> str:
        try:
            ip = ipaddress.ip_address(ip_address)
            
            if ip.is_private:
                return "XX"
            
            ip_str = str(ip)
            first_octet = int(ip_str.split('.')[0])
            
            country_map = {
                (1, 126): 'US', (128, 191): 'CN', (192, 223): 'DE',
                (224, 239): 'BR', (240, 255): 'KR'
            }
            
            for (start, end), country in country_map.items():
                if start <= first_octet <= end:
                    return country
            
            return 'XX'
            
        except Exception as e:
            logger.error(f"Error determining country for IP {ip_address}: {e}")
            return 'XX'
    
    def check_ip(self, ip_address: str) -> Dict:
        country_code = self._get_country_from_ip(ip_address)
        country_name = self._country_names.get(country_code, 'Unknown')
        
        blocked = False
        matched_rule = None
        
        for rule in self._rules:
            if country_code in rule.country_codes:
                if rule.action == "block" and not rule.is_whitelist:
                    blocked = True
                    matched_rule = rule
                    break
        
        return {
            "ip": ip_address,
            "country_code": country_code,
            "country_name": country_name,
            "blocked": blocked,
            "rule_id": matched_rule.rule_id if matched_rule else None,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def add_rule(
        self,
        action: str,
        country_codes: List[str],
        is_whitelist: bool = False,
        description: str = ""
    ) -> str:
        import uuid
        rule_id = f"rule_{uuid.uuid4().hex[:8]}"
        
        rule = GeoBlockingRule(
            rule_id=rule_id,
            action=action,
            country_codes=country_codes,
            is_whitelist=is_whitelist,
            description=description,
            created_at=datetime.utcnow()
        )
        
        self._rules.append(rule)
        return rule_id
    
    def remove_rule(self, rule_id: str) -> bool:
        for i, rule in enumerate(self._rules):
            if rule.rule_id == rule_id:
                del self._rules[i]
                return True
        return False
    
    def get_rules(self) -> List[Dict]:
        return [
            {
                "rule_id": r.rule_id,
                "action": r.action,
                "country_codes": r.country_codes,
                "is_whitelist": r.is_whitelist,
                "description": r.description,
                "created_at": r.created_at.isoformat()
            }
            for r in self._rules
        ]


geo_blocking_service = GeoBlockingService()


class HoneypotService:
    def __init__(self):
        self._endpoints: Dict[str, Dict] = {}
        self._traps: List[Dict] = []
        self._init_honeypots()
    
    def _init_honeypots(self):
        self._endpoints = {
            "/admin.php": {
                "enabled": True,
                "trap_type": "sql_injection",
                "response": "SQL syntax error detected"
            },
            "/api/debug": {
                "enabled": True,
                "trap_type": "information_disclosure",
                "response": "Debug mode is enabled"
            },
            "/backup.sql": {
                "enabled": True,
                "trap_type": "file_access",
                "response": "Access denied"
            },
            "/phpinfo.php": {
                "enabled": True,
                "trap_type": "information_disclosure",
                "response": "Server configuration information"
            },
            "/wp-admin/": {
                "enabled": True,
                "trap_type": "brute_force",
                "response": "Login failed"
            }
        }
    
    def check_endpoint(self, path: str) -> Optional[Dict]:
        for endpoint, config in self._endpoints.items():
            if endpoint in path and config["enabled"]:
                return {
                    "endpoint": endpoint,
                    "trap_type": config["trap_type"],
                    "response": config["response"],
                    "is_honeypot": True
                }
        return None
    
    def log_breach(self, ip_address: str, path: str, trap_type: str):
        breach = {
            "ip_address": ip_address,
            "path": path,
            "trap_type": trap_type,
            "timestamp": datetime.utcnow().isoformat(),
            "severity": "high"
        }
        self._traps.append(breach)
        
        if len(self._traps) > 1000:
            self._traps = self._traps[-1000:]
        
        logger.warning(f"Honeypot triggered: {ip_address} accessed {path} ({trap_type})")
        
        return breach
    
    def get_traps(self) -> List[Dict]:
        return self._traps[-100:]
    
    def add_honeypot(self, path: str, trap_type: str, response: str) -> bool:
        if path in self._endpoints:
            return False
        
        self._endpoints[path] = {
            "enabled": True,
            "trap_type": trap_type,
            "response": response
        }
        return True
    
    def remove_honeypot(self, path: str) -> bool:
        if path in self._endpoints:
            del self._endpoints[path]
            return True
        return False


honeypot_service = HoneypotService()