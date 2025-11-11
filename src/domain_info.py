"""
Domain OSINT Information Extraction

Provides WHOIS, DNS, and domain metadata for phishing detection analysis.
"""
import logging
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, Optional

logger = logging.getLogger("domain_info")

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    logger.warning("python-whois not installed. WHOIS lookups will be unavailable.")

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    logger.warning("dnspython not installed. DNS lookups will be unavailable.")


def get_domain_info(url: str) -> Dict:
    """
    Extract domain metadata including WHOIS and DNS information.
    
    Args:
        url: Full URL to analyze
        
    Returns:
        Dictionary with domain metadata
    """
    result = {
        "registrar": "unknown",
        "domain_age_days": None,
        "created": "unknown",
        "expires": "unknown",
        "nameservers": [],
        "mx_records": []
    }
    
    try:
        # Extract domain from URL
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Remove www prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        if not domain:
            logger.warning(f"Could not extract domain from URL: {url}")
            return result
        
        # WHOIS lookup
        if WHOIS_AVAILABLE:
            try:
                w = whois.whois(domain)
                
                # Registrar
                if hasattr(w, 'registrar') and w.registrar:
                    result["registrar"] = str(w.registrar)
                
                # Creation date
                if hasattr(w, 'creation_date') and w.creation_date:
                    creation_date = w.creation_date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    
                    if creation_date:
                        result["created"] = creation_date.strftime("%Y-%m-%d")
                        # Calculate age
                        age = (datetime.now() - creation_date).days
                        result["domain_age_days"] = age
                
                # Expiration date
                if hasattr(w, 'expiration_date') and w.expiration_date:
                    expiration_date = w.expiration_date
                    if isinstance(expiration_date, list):
                        expiration_date = expiration_date[0]
                    
                    if expiration_date:
                        result["expires"] = expiration_date.strftime("%Y-%m-%d")
                
            except Exception as e:
                logger.warning(f"WHOIS lookup failed for {domain}: {e}")
        
        # DNS lookups
        if DNS_AVAILABLE:
            try:
                # Nameservers
                ns_records = dns.resolver.resolve(domain, 'NS')
                result["nameservers"] = [str(ns.target).rstrip('.') for ns in ns_records]
            except Exception as e:
                logger.debug(f"NS lookup failed for {domain}: {e}")
            
            try:
                # MX records
                mx_records = dns.resolver.resolve(domain, 'MX')
                result["mx_records"] = [str(mx.exchange).rstrip('.') for mx in mx_records]
            except Exception as e:
                logger.debug(f"MX lookup failed for {domain}: {e}")
                result["mx_records"] = ["none"]
        
        return result
        
    except Exception as e:
        logger.error(f"Error getting domain info for {url}: {e}")
        return result
