"""
SSL Certificate Information Extraction

Extracts SSL/TLS certificate metadata for security analysis.
"""
import ssl
import socket
import logging
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict

logger = logging.getLogger("cert_info")


def get_certificate_metadata(url: str) -> Dict:
    """
    Extract SSL certificate metadata from a URL.
    
    Args:
        url: Full URL to analyze
        
    Returns:
        Dictionary with certificate metadata
    """
    result = {
        "ssl_issuer": "unknown",
        "ssl_valid_from": "unknown",
        "ssl_valid_to": "unknown",
        "ssl_enabled": False
    }
    
    try:
        # Extract hostname from URL
        parsed = urlparse(url)
        hostname = parsed.netloc or parsed.path
        
        # Remove port if present
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        
        if not hostname:
            logger.warning(f"Could not extract hostname from URL: {url}")
            return result
        
        # Only check HTTPS URLs
        if not url.startswith('https://'):
            result["ssl_enabled"] = False
            result["ssl_issuer"] = "HTTP only (no SSL)"
            return result
        
        # Create SSL context
        context = ssl.create_default_context()
        
        # Connect and get certificate
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                result["ssl_enabled"] = True
                
                # Extract issuer
                if 'issuer' in cert:
                    issuer_dict = dict(x[0] for x in cert['issuer'])
                    result["ssl_issuer"] = issuer_dict.get('commonName', 'unknown')
                
                # Extract validity dates
                if 'notBefore' in cert:
                    try:
                        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                        result["ssl_valid_from"] = not_before.strftime("%Y-%m-%d")
                    except:
                        result["ssl_valid_from"] = cert['notBefore']
                
                if 'notAfter' in cert:
                    try:
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        result["ssl_valid_to"] = not_after.strftime("%Y-%m-%d")
                    except:
                        result["ssl_valid_to"] = cert['notAfter']
        
        return result
        
    except socket.timeout:
        logger.warning(f"SSL connection timeout for {url}")
        result["ssl_issuer"] = "Connection timeout"
        return result
    except ssl.SSLError as e:
        logger.warning(f"SSL error for {url}: {e}")
        result["ssl_issuer"] = f"SSL Error: {str(e)[:50]}"
        return result
    except Exception as e:
        logger.warning(f"Error getting certificate for {url}: {e}")
        result["ssl_issuer"] = "Certificate unavailable"
        return result
