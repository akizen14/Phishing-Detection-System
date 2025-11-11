"""
Reverse DNS and IP Resolution

Provides IP resolution and reverse DNS lookups for hosting analysis.
"""
import socket
import logging
from urllib.parse import urlparse
from typing import Optional, Tuple

logger = logging.getLogger("reverse_dns")


def resolve_ip(url: str) -> Optional[str]:
    """
    Resolve URL to IP address.
    
    Args:
        url: Full URL to resolve
        
    Returns:
        IP address as string, or None if resolution fails
    """
    try:
        # Extract hostname from URL
        parsed = urlparse(url)
        hostname = parsed.netloc or parsed.path
        
        # Remove port if present
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        
        if not hostname:
            logger.warning(f"Could not extract hostname from URL: {url}")
            return None
        
        # Resolve to IP
        ip = socket.gethostbyname(hostname)
        return ip
        
    except socket.gaierror as e:
        logger.warning(f"DNS resolution failed for {url}: {e}")
        return None
    except Exception as e:
        logger.error(f"Error resolving IP for {url}: {e}")
        return None


def reverse_dns(ip: str) -> str:
    """
    Perform reverse DNS lookup on an IP address.
    
    Args:
        ip: IP address to lookup
        
    Returns:
        Hostname from PTR record, or "unknown" if lookup fails
    """
    if not ip:
        return "unknown"
    
    try:
        # Perform reverse DNS lookup
        hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
        return hostname
        
    except socket.herror:
        logger.debug(f"No PTR record for {ip}")
        return "no PTR record"
    except Exception as e:
        logger.debug(f"Reverse DNS failed for {ip}: {e}")
        return "unknown"


def get_hosting_info(url: str) -> Tuple[Optional[str], str]:
    """
    Get IP and reverse DNS information for a URL.
    
    Args:
        url: Full URL to analyze
        
    Returns:
        Tuple of (ip_address, reverse_dns_hostname)
    """
    ip = resolve_ip(url)
    reverse = reverse_dns(ip) if ip else "unknown"
    return ip, reverse
