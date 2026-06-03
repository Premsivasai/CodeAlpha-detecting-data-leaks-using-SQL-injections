from app.config import settings
import logging
from typing import Optional, Dict, List
from datetime import datetime
import httpx
import asyncio

logger = logging.getLogger(__name__)


class ThreatIntelService:
    def __init__(self):
        self.cache = {}
        self.cache_ttl = 3600
    
    async def check_ip_reputation(self, ip: str) -> Dict:
        results = {}
        
        if settings.ABUSEIPDB_ENABLED:
            results["abuseipdb"] = await self._check_abuseipdb(ip)
        
        if settings.ALIENVAULT_ENABLED:
            results["alienvault"] = await self._check_alienvault(ip)
        
        if settings.VIRUSTOTAL_ENABLED:
            results["virustotal"] = await self._check_virustotal_ip(ip)
        
        overall_score = self._calculate_reputation_score(results)
        
        return {
            "ip": ip,
            "reputation_score": overall_score,
            "sources": results,
            "checked_at": datetime.utcnow().isoformat()
        }
    
    async def _check_abuseipdb(self, ip: str) -> Optional[Dict]:
        if not settings.ABUSEIPDB_API_KEY:
            return None
        
        try:
            url = f"https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": settings.ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            }
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(url, headers=headers, params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "score": data.get("data", {}).get("abuseConfidencePercentage", 0),
                        "reports": data.get("data", {}).get("totalReports", 0),
                        "is_whitelisted": data.get("data", {}).get("isWhitelisted", False),
                        "is_spam": data.get("data", {}).get("isSpam", False),
                        "is_tor": data.get("data", {}).get("isTor", False),
                        "country_code": data.get("data", {}).get("countryCode"),
                        "isp": data.get("data", {}).get("isp"),
                        "domain": data.get("data", {}).get("domain")
                    }
        except Exception as e:
            logger.warning(f"AbuseIPDB check failed: {e}")
        
        return None
    
    async def _check_alienvault(self, ip: str) -> Optional[Dict]:
        if not settings.ALIENVAULT_API_KEY:
            return None
        
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
            headers = {"X-OTX-API-KEY": settings.ALIENVAULT_API_KEY}
            
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(url, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    pulse_count = len(data.get("pulse_info", {}).get("count", 0))
                    return {
                        "pulse_count": pulse_count,
                        "reputation": data.get("reputation", 0),
                        "country_code": data.get("country_code"),
                        "asn": data.get("asn"),
                        "city": data.get("city")
                    }
        except Exception as e:
            logger.warning(f"AlienVault check failed: {e}")
        
        return None
    
    async def _check_virustotal_ip(self, ip: str) -> Optional[Dict]:
        if not settings.VIRUSTOTAL_API_KEY:
            return None
        
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
            
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(url, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    last_analysis = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    return {
                        "malicious": last_analysis.get("malicious", 0),
                        "suspicious": last_analysis.get("suspicious", 0),
                        "harmless": last_analysis.get("harmless", 0),
                        "undetected": last_analysis.get("undetected", 0),
                        "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 0)
                    }
        except Exception as e:
            logger.warning(f"VirusTotal check failed: {e}")
        
        return None
    
    def _calculate_reputation_score(self, results: Dict) -> float:
        scores = []
        
        if abuseipdb := results.get("abuseipdb"):
            if abuseipdb.get("score", 0) > 50:
                scores.append(0.2)
            elif abuseipdb.get("score", 0) > 0:
                scores.append(0.6)
            else:
                scores.append(0.9)
        
        if alienvault := results.get("alienvault"):
            rep = alienvault.get("reputation", 0)
            if rep < -50:
                scores.append(0.1)
            elif rep < 0:
                scores.append(0.4)
            else:
                scores.append(0.8)
        
        if virustotal := results.get("virustotal"):
            malicious = virustotal.get("malicious", 0)
            undetected = virustotal.get("undetected", 1)
            if malicious > undetected / 2:
                scores.append(0.2)
            elif malicious > 0:
                scores.append(0.5)
            else:
                scores.append(0.9)
        
        if not scores:
            return 0.5
        
        return sum(scores) / len(scores)
    
    async def check_domain_reputation(self, domain: str) -> Dict:
        results = {}
        
        if settings.VIRUSTOTAL_ENABLED:
            results["virustotal"] = await self._check_virustotal_domain(domain)
        
        return {
            "domain": domain,
            "reputation_score": results.get("virustotal", {}).get("reputation", 50) / 100.0,
            "sources": results,
            "checked_at": datetime.utcnow().isoformat()
        }
    
    async def _check_virustotal_domain(self, domain: str) -> Optional[Dict]:
        if not settings.VIRUSTOTAL_API_KEY:
            return None
        
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
            
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(url, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    last_analysis = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    return {
                        "malicious": last_analysis.get("malicious", 0),
                        "suspicious": last_analysis.get("suspicious", 0),
                        "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 50)
                    }
        except Exception as e:
            logger.warning(f"VirusTotal domain check failed: {e}")
        
        return None
    
    async def sync_misp_feed(self) -> Dict:
        if not settings.MISP_ENABLED:
            return {"status": "skipped"}
        
        if not settings.MISP_URL or not settings.MISP_API_KEY:
            return {"error": "MISP not configured"}
        
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    f"{settings.MISP_URL}/attributes/restSearch",
                    headers={"Authorization": settings.MISP_API_KEY},
                    params={"type": "ip-dst", "limit": 100}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    ioc_count = len(data.get("response", []))
                    return {
                        "status": "synced",
                        "ioc_count": ioc_count,
                        "timestamp": datetime.utcnow().isoformat()
                    }
        except Exception as e:
            logger.error(f"MISP sync failed: {e}")
            return {"error": str(e)}
        
        return {"status": "error"}


threat_intel_service = ThreatIntelService()