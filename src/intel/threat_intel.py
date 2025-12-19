import requests
import json
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging
from pathlib import Path
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatIntelligence:
    """Threat Intelligence integration for enriching IOCs."""
    
    def __init__(self, config):
        self.config = config
        self.cache_dir = Path(".cache/threat_intel")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_ttl = timedelta(hours=24)  # Cache TTL: 24 hours
        
        # Initialize API clients
        self.vt_client = self._init_virustotal()
        self.otx_client = self._init_otx()
        
    def _init_virustotal(self):
        """Initialize VirusTotal client."""
        api_key = self.config.get("VIRUSTOTAL_API_KEY")
        if not api_key:
            logger.warning("VirusTotal API key not configured. Some features will be disabled.")
            return None
            
        class VirusTotalClient:
            BASE_URL = "https://www.virustotal.com/api/v3"
            
            def __init__(self, api_key):
                self.api_key = api_key
                self.session = requests.Session()
                self.session.headers.update({
                    "x-apikey": self.api_key,
                    "Accept": "application/json"
                })
                
            def get_domain_info(self, domain: str) -> Optional[Dict]:
                """Get domain reputation from VirusTotal."""
                try:
                    response = self.session.get(f"{self.BASE_URL}/domains/{domain}")
                    response.raise_for_status()
                    return response.json()
                except requests.RequestException as e:
                    logger.error(f"VirusTotal API error: {e}")
                    return None
                    
            def get_ip_info(self, ip: str) -> Optional[Dict]:
                """Get IP address reputation from VirusTotal."""
                try:
                    response = self.session.get(f"{self.BASE_URL}/ip_addresses/{ip}")
                    response.raise_for_status()
                    return response.json()
                except requests.RequestException as e:
                    logger.error(f"VirusTotal API error: {e}")
                    return None
                    
            def get_file_info(self, file_hash: str) -> Optional[Dict]:
                """Get file reputation from VirusTotal."""
                try:
                    response = self.session.get(f"{self.BASE_URL}/files/{file_hash}")
                    response.raise_for_status()
                    return response.json()
                except requests.RequestException as e:
                    logger.error(f"VirusTotal API error: {e}")
                    return None
        
        return VirusTotalClient(api_key) if api_key else None
    
    def _init_otx(self):
        """Initialize AlienVault OTX client."""
        api_key = self.config.get("ALIENVAULT_OTX_KEY")
        if not api_key:
            logger.warning("AlienVault OTX API key not configured. Some features will be disabled.")
            return None
            
        class OTXClient:
            BASE_URL = "https://otx.alienvault.com/api/v1"
            
            def __init__(self, api_key):
                self.api_key = api_key
                self.session = requests.Session()
                self.session.headers.update({
                    "X-OTX-API-KEY": self.api_key,
                    "Accept": "application/json"
                })
                
            def get_indicator_details(self, indicator_type: str, indicator: str) -> Optional[Dict]:
                """Get indicator details from OTX."""
                try:
                    response = self.session.get(
                        f"{self.BASE_URL}/indicators/{indicator_type}/{indicator}/general"
                    )
                    response.raise_for_status()
                    return response.json()
                except requests.RequestException as e:
                    logger.error(f"OTX API error: {e}")
                    return None
        
        return OTXClient(api_key) if api_key else None
    
    def _get_cached_result(self, indicator: str) -> Optional[Dict]:
        """Get cached threat intelligence result."""
        cache_file = self.cache_dir / f"{indicator}.json"
        if not cache_file.exists():
            return None
            
        # Check if cache is still valid
        cache_time = datetime.fromtimestamp(cache_file.stat().st_mtime)
        if datetime.now() - cache_time > self.cache_ttl:
            return None
            
        try:
            with open(cache_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to read cache for {indicator}: {e}")
            return None
    
    def _save_to_cache(self, indicator: str, data: Dict):
        """Save threat intelligence result to cache."""
        cache_file = self.cache_dir / f"{indicator}.json"
        try:
            with open(cache_file, 'w') as f:
                json.dump(data, f)
        except IOError as e:
            logger.warning(f"Failed to save cache for {indicator}: {e}")
    
    def enrich_ioc(self, ioc_type: str, value: str) -> Dict:
        """Enrich an IOC with threat intelligence."""
        result = {
            "value": value,
            "type": ioc_type,
            "sources": {},
            "malicious": False,
            "score": 0,
            "last_updated": datetime.utcnow().isoformat()
        }
        
        # Check cache first
        cached = self._get_cached_result(f"{ioc_type}_{value}")
        if cached:
            return cached
        
        # Enrich based on IOC type
        if ioc_type == "ip":
            result = self._enrich_ip(value, result)
        elif ioc_type == "domain":
            result = self._enrich_domain(value, result)
        elif ioc_type in ["md5", "sha1", "sha256"]:
            result = self._enrich_hash(value, result)
        elif ioc_type == "url":
            result = self._enrich_url(value, result)
        elif ioc_type == "email":
            result = self._enrich_email(value, result)
        
        # Save to cache
        self._save_to_cache(f"{ioc_type}_{value}", result)
        return result
    
    def _enrich_ip(self, ip: str, result: Dict) -> Dict:
        """Enrich an IP address with threat intelligence."""
        # Check if it's a private IP
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                result["sources"]["internal"] = {"is_private": True}
                return result
        except ValueError:
            pass
        
        # Check VirusTotal
        if self.vt_client:
            try:
                vt_data = self.vt_client.get_ip_info(ip)
                if vt_data:
                    result["sources"]["virustotal"] = vt_data
                    # Extract relevant info from VT response
                    if "data" in vt_data and "attributes" in vt_data["data"]:
                        attrs = vt_data["data"]["attributes"]
                        result["last_analysis_stats"] = attrs.get("last_analysis_stats", {})
                        malicious = attrs.get("last_analysis_stats", {}).get("malicious", 0)
                        if malicious > 0:
                            result["malicious"] = True
                            result["score"] = min(100, malicious * 10)  # Simple scoring
            except Exception as e:
                logger.error(f"Error enriching IP {ip} with VirusTotal: {e}")
        
        # Check OTX
        if self.otx_client:
            try:
                otx_data = self.otx_client.get_indicator_details("IPv4", ip)
                if otx_data:
                    result["sources"]["otx"] = otx_data
                    # Extract pulse info from OTX
                    if "pulse_info" in otx_data and "count" in otx_data["pulse_info"]:
                        pulse_count = otx_data["pulse_info"]["count"]
                        if pulse_count > 0 and not result["malicious"]:
                            result["malicious"] = True
                            result["score"] = min(100, pulse_count * 5)  # Adjust score
            except Exception as e:
                logger.error(f"Error enriching IP {ip} with OTX: {e}")
        
        return result
    
    def _enrich_domain(self, domain: str, result: Dict) -> Dict:
        """Enrich a domain with threat intelligence."""
        # Check VirusTotal
        if self.vt_client:
            try:
                vt_data = self.vt_client.get_domain_info(domain)
                if vt_data:
                    result["sources"]["virustotal"] = vt_data
                    # Extract relevant info from VT response
                    if "data" in vt_data and "attributes" in vt_data["data"]:
                        attrs = vt_data["data"]["attributes"]
                        result["last_analysis_stats"] = attrs.get("last_analysis_stats", {})
                        malicious = attrs.get("last_analysis_stats", {}).get("malicious", 0)
                        if malicious > 0:
                            result["malicious"] = True
                            result["score"] = min(100, malicious * 10)  # Simple scoring
            except Exception as e:
                logger.error(f"Error enriching domain {domain} with VirusTotal: {e}")
        
        # Check OTX
        if self.otx_client:
            try:
                otx_data = self.otx_client.get_indicator_details("domain", domain)
                if otx_data:
                    result["sources"]["otx"] = otx_data
                    # Extract pulse info from OTX
                    if "pulse_info" in otx_data and "count" in otx_data["pulse_info"]:
                        pulse_count = otx_data["pulse_info"]["count"]
                        if pulse_count > 0 and not result["malicious"]:
                            result["malicious"] = True
                            result["score"] = min(100, pulse_count * 5)  # Adjust score
            except Exception as e:
                logger.error(f"Error enriching domain {domain} with OTX: {e}")
        
        return result
    
    def _enrich_hash(self, file_hash: str, result: Dict) -> Dict:
        """Enrich a file hash with threat intelligence."""
        # Check VirusTotal
        if self.vt_client:
            try:
                vt_data = self.vt_client.get_file_info(file_hash)
                if vt_data:
                    result["sources"]["virustotal"] = vt_data
                    # Extract relevant info from VT response
                    if "data" in vt_data and "attributes" in vt_data["data"]:
                        attrs = vt_data["data"]["attributes"]
                        result["last_analysis_stats"] = attrs.get("last_analysis_stats", {})
                        malicious = attrs.get("last_analysis_stats", {}).get("malicious", 0)
                        if malicious > 0:
                            result["malicious"] = True
                            result["score"] = min(100, malicious * 10)  # Simple scoring
            except Exception as e:
                logger.error(f"Error enriching hash {file_hash} with VirusTotal: {e}")
        
        return result
    
    def _enrich_url(self, url: str, result: Dict) -> Dict:
        """Enrich a URL with threat intelligence."""
        # For now, we'll just extract the domain and check that
        # In a real implementation, we'd check URL-specific threat feeds
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
            if domain:
                domain_result = self.enrich_ioc("domain", domain)
                if domain_result.get("malicious", False):
                    result["malicious"] = True
                    result["score"] = max(result.get("score", 0), domain_result.get("score", 0))
                    result["sources"]["domain_check"] = domain_result["sources"]
        except Exception as e:
            logger.error(f"Error enriching URL {url}: {e}")
        
        return result
    
    def _enrich_email(self, email: str, result: Dict) -> Dict:
        """Enrich an email address with threat intelligence."""
        # In a real implementation, check email reputation services
        # For now, we'll just check the domain part
        try:
            domain = email.split('@')[-1]
            if domain:
                domain_result = self.enrich_ioc("domain", domain)
                if domain_result.get("malicious", False):
                    result["malicious"] = True
                    result["score"] = max(result.get("score", 0), domain_result.get("score", 0))
                    result["sources"]["domain_check"] = domain_result["sources"]
        except Exception as e:
            logger.error(f"Error enriching email {email}: {e}")
        
        return result

# Example usage
if __name__ == "__main__":
    # Example configuration
    config = {
        "VIRUSTOTAL_API_KEY": "your-virustotal-api-key",
        "ALIENVAULT_OTX_KEY": "your-otx-api-key"
    }
    
    ti = ThreatIntelligence(config)
    
    # Example enrichment
    results = ti.enrich_ioc("ip", "8.8.8.8")
    print(json.dumps(results, indent=2))
