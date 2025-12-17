"""Alert enrichment with GeoIP, ASN, and threat intelligence."""
import logging
import ipaddress
from typing import Any, Dict, Optional
from functools import lru_cache
import time

from src.common.web import RetrySession

logger = logging.getLogger(__name__)


class GeoIPEnricher:
    """Enrich alerts with GeoIP information using free services."""
    
    def __init__(self):
        self.session = RetrySession(max_retries=2, timeout=3)
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_ttl = 3600  # 1 hour cache
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except Exception:
            return False
    
    @lru_cache(maxsize=1000)
    def _get_geoip_cached(self, ip: str, cache_key: str) -> Optional[Dict[str, Any]]:
        """Cached GeoIP lookup (using lru_cache for in-memory cache)."""
        # Check our manual cache first (for TTL)
        if cache_key in self._cache:
            cached_data = self._cache[cache_key]
            if time.time() - cached_data.get("_cached_at", 0) < self._cache_ttl:
                return cached_data.get("data")
        
        # Try ipapi.co (free, no API key required)
        try:
            url = f"https://ipapi.co/{ip}/json/"
            response = self.session.request("GET", url, timeout=3)
            if response.status_code == 200:
                data = response.json()
                
                # Check for rate limit
                if "error" in data:
                    logger.debug(f"GeoIP API error for {ip}: {data.get('reason', 'Unknown')}")
                    return None
                
                geo_data = {
                    "country": data.get("country_name"),
                    "country_code": data.get("country_code"),
                    "region": data.get("region"),
                    "city": data.get("city"),
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude"),
                    "asn": data.get("asn"),
                    "org": data.get("org"),
                    "timezone": data.get("timezone")
                }
                
                # Cache result
                self._cache[cache_key] = {
                    "data": geo_data,
                    "_cached_at": time.time()
                }
                
                return geo_data
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip}: {e}")
        
        return None
    
    def enrich(self, ip: str) -> Dict[str, Any]:
        """
        Enrich IP address with GeoIP information.
        
        Args:
            ip: IP address string
            
        Returns:
            Dict with geo information or empty dict
        """
        if not ip:
            return {}
        
        # Skip private IPs
        if self._is_private_ip(ip):
            return {
                "is_internal": True,
                "country": "Internal",
                "country_code": "INT"
            }
        
        cache_key = f"geoip:{ip}"
        geo_data = self._get_geoip_cached(ip, cache_key)
        
        if geo_data:
            geo_data["is_internal"] = False
            return geo_data
        
        return {
            "is_internal": False,
            "country": "Unknown",
            "country_code": "UNK"
        }


class ThreatIntelligenceEnricher:
    """Enrich alerts with threat intelligence (basic implementation)."""
    
    def __init__(self):
        self.session = RetrySession(max_retries=1, timeout=2)
        self._known_malicious_ips: set = set()  # Can be loaded from feeds
        self._known_malicious_domains: set = set()
    
    def _check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """
        Check IP reputation (basic implementation).
        
        Can be extended with:
        - AbuseIPDB API
        - VirusTotal API
        - Custom threat feeds
        """
        if ip in self._known_malicious_ips:
            return {
                "is_malicious": True,
                "reputation": "malicious",
                "source": "internal_blacklist"
            }
        
        # Placeholder for future API integration
        return {
            "is_malicious": False,
            "reputation": "unknown"
        }
    
    def enrich(self, ip: str, domain: Optional[str] = None) -> Dict[str, Any]:
        """
        Enrich with threat intelligence.
        
        Args:
            ip: IP address
            domain: Optional domain name
            
        Returns:
            Threat intelligence data
        """
        result = {}
        
        if ip:
            result.update(self._check_ip_reputation(ip))
        
        if domain and domain in self._known_malicious_domains:
            result["domain_reputation"] = "malicious"
            result["is_malicious"] = True
        
        return result


# Global enricher instances
_geoip_enricher: Optional[GeoIPEnricher] = None
_threat_intel_enricher: Optional[ThreatIntelligenceEnricher] = None


def get_geoip_enricher() -> GeoIPEnricher:
    """Get or create global GeoIP enricher."""
    global _geoip_enricher
    if _geoip_enricher is None:
        _geoip_enricher = GeoIPEnricher()
    return _geoip_enricher


def get_threat_intel_enricher() -> ThreatIntelligenceEnricher:
    """Get or create global threat intel enricher."""
    global _threat_intel_enricher
    if _threat_intel_enricher is None:
        _threat_intel_enricher = ThreatIntelligenceEnricher()
    return _threat_intel_enricher


def enrich_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich alert with GeoIP and threat intelligence.
    
    Args:
        alert: Normalized alert dictionary
        
    Returns:
        Enriched alert with additional fields
    """
    # Prefer top-level src_ip/dest_ip if available, fallback to srcip/agent.ip
    srcip = alert.get("src_ip") or alert.get("srcip", "")
    agent = alert.get("agent", {})
    dstip = alert.get("dest_ip") or agent.get("ip", "")
    http_context = alert.get("http")
    
    enrichment_data = {
        "source_geo": {},
        "destination_geo": {},
        "threat_intel": {}
    }
    
    # Enrich source IP
    if srcip:
        geo_enricher = get_geoip_enricher()
        enrichment_data["source_geo"] = geo_enricher.enrich(srcip)
        
        threat_enricher = get_threat_intel_enricher()
        enrichment_data["threat_intel"].update(
            threat_enricher.enrich(srcip)
        )
    
    # Enrich destination IP (if external)
    if dstip and not dstip.startswith(("192.168.", "10.", "172.16.")):
        geo_enricher = get_geoip_enricher()
        enrichment_data["destination_geo"] = geo_enricher.enrich(dstip)
    
    # Enrich domain from HTTP context
    if http_context:
        hostname = http_context.get("hostname", "")
        if hostname:
            threat_enricher = get_threat_intel_enricher()
            enrichment_data["threat_intel"].update(
                threat_enricher.enrich(None, domain=hostname)
            )
    
    return enrichment_data

