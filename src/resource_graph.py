"""
Resource Graph Signature Extraction

Extracts structural signatures from resource URLs (JS, CSS, images, fonts)
for pages with minimal DOM structure (dynamically loaded content).
"""
import re
from typing import Set
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup


def extract_resource_signature(html: str, base_url: str = "") -> bytes:
    """
    Extract resource signature from HTML by collecting all resource URLs.
    
    This is useful for phishing pages that load content dynamically and have
    minimal initial DOM structure.
    
    Args:
        html: Raw HTML content
        base_url: Base URL for resolving relative paths
        
    Returns:
        Sorted, space-separated list of normalized resource URLs as UTF-8 bytes
    """
    soup = BeautifulSoup(html, "html.parser")
    resources = set()
    
    # Extract JavaScript resources
    for script in soup.find_all("script", src=True):
        resources.add(normalize_resource_url(script["src"], base_url))
    
    # Extract CSS resources
    for link in soup.find_all("link", rel="stylesheet", href=True):
        resources.add(normalize_resource_url(link["href"], base_url))
    
    for link in soup.find_all("link", href=True):
        if link.get("rel") and "stylesheet" in link.get("rel"):
            resources.add(normalize_resource_url(link["href"], base_url))
    
    # Extract image resources
    for img in soup.find_all("img", src=True):
        resources.add(normalize_resource_url(img["src"], base_url))
    
    # Extract font resources from CSS @font-face (inline styles)
    for style in soup.find_all("style"):
        if style.string:
            font_urls = re.findall(r'url\(["\']?([^"\')]+)["\']?\)', style.string)
            for url in font_urls:
                resources.add(normalize_resource_url(url, base_url))
    
    # Extract preload/prefetch resources
    for link in soup.find_all("link", href=True):
        rel = link.get("rel", [])
        if isinstance(rel, list):
            rel = " ".join(rel)
        if any(x in rel for x in ["preload", "prefetch", "dns-prefetch", "preconnect"]):
            resources.add(normalize_resource_url(link["href"], base_url))
    
    # Extract iframe sources
    for iframe in soup.find_all("iframe", src=True):
        resources.add(normalize_resource_url(iframe["src"], base_url))
    
    # Extract video/audio sources
    for media in soup.find_all(["video", "audio"], src=True):
        resources.add(normalize_resource_url(media["src"], base_url))
    
    for source in soup.find_all("source", src=True):
        resources.add(normalize_resource_url(source["src"], base_url))
    
    # Remove empty strings and sort for consistency
    resources = sorted([r for r in resources if r])
    
    # Create signature: space-separated resource URLs
    signature = " ".join(resources)
    
    print(f"RESOURCE SIGNATURE: {len(resources)} resources, {len(signature)} bytes")
    
    return signature.encode("utf-8")


def normalize_resource_url(url: str, base_url: str = "") -> str:
    """
    Normalize a resource URL for consistent comparison.
    
    Args:
        url: Resource URL (may be relative or absolute)
        base_url: Base URL for resolving relative paths
        
    Returns:
        Normalized URL string
    """
    # Skip data URIs and empty strings
    if not url or url.startswith("data:") or url.startswith("blob:"):
        return ""
    
    # Remove query parameters and fragments for structural comparison
    url = url.split("?")[0].split("#")[0]
    
    # Parse URL
    parsed = urlparse(url)
    
    # If it's a protocol-relative URL (//example.com/...)
    if url.startswith("//"):
        return f"https:{url}"
    
    # If it's a relative URL and we have a base
    if not parsed.scheme and base_url:
        url = urljoin(base_url, url)
        parsed = urlparse(url)
    
    # Extract domain and path only (ignore scheme for CDN variations)
    if parsed.netloc:
        # Normalize domain (remove www prefix)
        domain = parsed.netloc.replace("www.", "")
        path = parsed.path
        return f"{domain}{path}"
    
    # Return path only for relative URLs without base
    return parsed.path


def get_resource_domains(html: str, base_url: str = "") -> Set[str]:
    """
    Extract unique domains from resource URLs.
    
    Useful for identifying third-party dependencies and CDN usage patterns.
    
    Args:
        html: Raw HTML content
        base_url: Base URL for resolving relative paths
        
    Returns:
        Set of unique domain names
    """
    soup = BeautifulSoup(html, "html.parser")
    domains = set()
    
    # Collect all resource URLs
    for tag in soup.find_all(["script", "link", "img", "iframe"]):
        url = tag.get("src") or tag.get("href")
        if url:
            parsed = urlparse(url)
            if parsed.netloc:
                domains.add(parsed.netloc.replace("www.", ""))
    
    return domains
