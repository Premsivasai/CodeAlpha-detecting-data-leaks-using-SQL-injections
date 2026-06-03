from app.config import settings
import logging
import hashlib
import secrets
from typing import Optional, Dict
from datetime import datetime
import asyncio

logger = logging.getLogger(__name__)


class ZeroTrustService:
    def __init__(self):
        self.device_cache = {}
        self.session_risk_scores = {}
    
    def generate_device_fingerprint(self, user_agent: str, ip: str, accept_language: str = None) -> str:
        components = [user_agent, ip]
        if accept_language:
            components.append(accept_language)
        
        fingerprint = "|".join(components)
        return hashlib.sha256(fingerprint.encode()).hexdigest()[:32]
    
    def calculate_session_risk(
        self,
        user_id: int,
        ip_address: str,
        user_agent: str,
        device_fingerprint: str,
        location: Optional[Dict] = None,
        time_since_login: int = 0
    ) -> Dict:
        risk_score = 0.0
        factors = []
        
        if settings.DEVICE_FINGERPRINT_ENABLED:
            is_known_device = self._is_known_device(user_id, device_fingerprint)
            if not is_known_device:
                risk_score += 0.3
                factors.append({"factor": "new_device", "weight": 0.3})
        
        if location:
            is_suspicious_location = self._check_location_anomaly(user_id, location)
            if is_suspicious_location:
                risk_score += 0.25
                factors.append({"factor": "suspicious_location", "weight": 0.25})
        
        ip_reputation = self._check_ip_reputation(ip_address)
        if ip_reputation < 0.3:
            risk_score += 0.35
            factors.append({"factor": "bad_ip_reputation", "weight": 0.35})
        
        time_risk = self._check_time_anomaly(time_since_login)
        if time_risk > 0:
            risk_score += time_risk
            factors.append({"factor": "unusual_time", "weight": time_risk})
        
        behavior_risk = self._check_behavior_pattern(user_id)
        risk_score += behavior_risk
        if behavior_risk > 0.1:
            factors.append({"factor": "behavior_anomaly", "weight": behavior_risk})
        
        risk_score = min(risk_score, 1.0)
        
        trust_level = "high" if risk_score < 0.3 else "medium" if risk_score < 0.6 else "low"
        
        mfa_required = risk_score > settings.TRUST_SCORE_THRESHOLD
        
        self.session_risk_scores[user_id] = risk_score
        
        return {
            "risk_score": risk_score,
            "trust_level": trust_level,
            "mfa_required": mfa_required,
            "factors": factors,
            "requires_verification": mfa_required
        }
    
    def _is_known_device(self, user_id: int, device_fingerprint: str) -> bool:
        cache_key = f"{user_id}:devices"
        known_devices = self.device_cache.get(cache_key, [])
        return device_fingerprint in known_devices
    
    def _check_location_anomaly(self, user_id: int, location: Dict) -> bool:
        cache_key = f"{user_id}:locations"
        previous_locations = self.device_cache.get(cache_key, [])
        
        if not previous_locations:
            return False
        
        current_country = location.get("country_code")
        return current_country not in previous_locations
    
    def _check_ip_reputation(self, ip_address: str) -> float:
        return 0.7
    
    def _check_time_anomaly(self, time_since_login: int) -> float:
        current_hour = datetime.utcnow().hour
        
        if 2 <= current_hour <= 6:
            return 0.2
        
        return 0.0
    
    def _check_behavior_pattern(self, user_id: int) -> float:
        recent_failures = self.device_cache.get(f"{user_id}:failures", 0)
        
        if recent_failures > 5:
            return 0.3
        elif recent_failures > 2:
            return 0.15
        
        return 0.0
    
    def get_session_trust_score(self, user_id: int) -> float:
        return self.session_risk_scores.get(user_id, 0.5)
    
    def update_session_trust(self, user_id: int, action_successful: bool):
        key = f"{user_id}:failures"
        
        if not action_successful:
            self.device_cache[key] = self.device_cache.get(key, 0) + 1
        else:
            if key in self.device_cache:
                del self.device_cache[key]
    
    def register_device(self, user_id: int, device_fingerprint: str):
        cache_key = f"{user_id}:devices"
        if cache_key not in self.device_cache:
            self.device_cache[cache_key] = []
        
        if device_fingerprint not in self.device_cache[cache_key]:
            self.device_cache[cache_key].append(device_fingerprint)
    
    def revoke_device(self, user_id: int, device_fingerprint: str):
        cache_key = f"{user_id}:devices"
        if cache_key in self.device_cache:
            self.device_cache[cache_key] = [
                d for d in self.device_cache[cache_key]
                if d != device_fingerprint
            ]


class AdaptiveMFAService:
    def __init__(self):
        self.mfa_challenges = {}
    
    def should_require_mfa(
        self,
        user_id: int,
        risk_score: float,
        is_new_device: bool,
        is_new_location: bool,
        transaction_value: float = 0
    ) -> Dict:
        mfa_triggered = False
        mfa_method = "totp"
        
        if risk_score > 0.7:
            mfa_triggered = True
            mfa_method = "strong"
        elif risk_score > 0.4:
            if is_new_device or is_new_location:
                mfa_triggered = True
        elif transaction_value > 1000:
            mfa_triggered = True
        elif is_new_device and risk_score > 0.2:
            mfa_triggered = True
        
        return {
            "mfa_required": mfa_triggered,
            "method": mfa_method if mfa_triggered else "none",
            "reason": self._get_mfa_reason(risk_score, is_new_device, is_new_location, transaction_value)
        }
    
    def _get_mfa_reason(
        self,
        risk_score: float,
        is_new_device: bool,
        is_new_location: bool,
        transaction_value: float
    ) -> str:
        if risk_score > 0.7:
            return "high_risk_session"
        if transaction_value > 1000:
            return "high_value_transaction"
        if is_new_device and is_new_location:
            return "new_device_and_location"
        if is_new_device:
            return "new_device"
        if is_new_location:
            return "new_location"
        return "normal"
    
    def generate_mfa_challenge(self, user_id: int, method: str = "totp") -> str:
        challenge_code = secrets.token_hex(8)
        
        self.mfa_challenges[user_id] = {
            "code": challenge_code,
            "method": method,
            "created_at": datetime.utcnow(),
            "attempts": 0
        }
        
        return challenge_code
    
    def verify_mfa_challenge(self, user_id: int, code: str) -> bool:
        challenge = self.mfa_challenges.get(user_id)
        
        if not challenge:
            return False
        
        if (datetime.utcnow() - challenge["created_at"]).total_seconds() > 300:
            del self.mfa_challenges[user_id]
            return False
        
        challenge["attempts"] += 1
        
        if challenge["attempts"] > 3:
            del self.mfa_challenges[user_id]
            return False
        
        if code == challenge["code"]:
            del self.mfa_challenges[user_id]
            return True
        
        return False


class BehavioralAnalyticsService:
    def __init__(self):
        self.user_profiles = {}
    
    def create_user_profile(self, user_id: int, baseline_data: Dict):
        self.user_profiles[user_id] = {
            "baseline": baseline_data,
            "behavioral_signatures": [],
            "last_updated": datetime.utcnow()
        }
    
    def analyze_behavior(
        self,
        user_id: int,
        current_action: Dict
    ) -> Dict:
        profile = self.user_profiles.get(user_id)
        
        if not profile:
            return {"anomaly_score": 0.0, "is_anomalous": False}
        
        baseline = profile["baseline"]
        
        action_patterns = current_action.get("patterns", {})
        
        score = 0.0
        anomalies = []
        
        if "request_timing" in action_patterns:
            baseline_timing = baseline.get("avg_request_time", 1.0)
            current_timing = action_patterns["request_timing"]
            if current_timing > baseline_timing * 3:
                score += 0.2
                anomalies.append("rapid_requests")
        
        if "endpoint_pattern" in action_patterns:
            common_endpoints = baseline.get("common_endpoints", [])
            if action_patterns["endpoint_pattern"] not in common_endpoints:
                score += 0.15
                anomalies.append("unusual_endpoint")
        
        if "data_volume" in action_patterns:
            baseline_volume = baseline.get("avg_data_volume", 0)
            if action_patterns["data_volume"] > baseline_volume * 5:
                score += 0.25
                anomalies.append("high_data_volume")
        
        score = min(score, 1.0)
        
        return {
            "anomaly_score": score,
            "is_anomalous": score > 0.3,
            "anomalies": anomalies
        }
    
    def update_baseline(self, user_id: int, action_data: Dict):
        if user_id in self.user_profiles:
            profile = self.user_profiles[user_id]
            baseline = profile["baseline"]
            
            if "request_time" in action_data:
                avg_time = baseline.get("avg_request_time", action_data["request_time"])
                baseline["avg_request_time"] = (avg_time * 0.9) + (action_data["request_time"] * 0.1)
            
            profile["last_updated"] = datetime.utcnow()


zero_trust_service = ZeroTrustService()
adaptive_mfa_service = AdaptiveMFAService()
behavioral_analytics_service = BehavioralAnalyticsService()