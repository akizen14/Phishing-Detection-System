"""
DOM extraction and sanitization pipeline.
"""
from typing import Optional

from src.render import render_page_source
from src.sanitize import tags_only_sanitizer, tags_attrs_sanitizer
from src.config import SANITIZE_MODE_TAGS_ONLY, SANITIZE_MODE_TAGS_ATTRS, DEFAULT_WAIT_SECONDS, DEFAULT_HEADLESS


def extract_sanitized_dom(
    url: str, 
    mode: str = SANITIZE_MODE_TAGS_ONLY, 
    wait_seconds: int = DEFAULT_WAIT_SECONDS, 
    headless: bool = DEFAULT_HEADLESS
) -> Optional[bytes]:
    """
    Extract and sanitize DOM from a URL.
    
    Pipeline: Render URL -> Sanitize HTML -> Return bytes for compression
    
    Args:
        url: URL to extract DOM from
        mode: Sanitization mode ('tags_only' or 'tags_attrs')
        wait_seconds: Seconds to wait for page load
        headless: Run browser in headless mode
        
    Returns:
        Sanitized DOM as bytes, or None if extraction fails
    """
    html = render_page_source(url, wait_seconds=wait_seconds, headless=headless)
    if not html:
        return None
    
    if mode == SANITIZE_MODE_TAGS_ONLY:
        return tags_only_sanitizer(html)
    elif mode == SANITIZE_MODE_TAGS_ATTRS:
        return tags_attrs_sanitizer(html)
    else:
        raise ValueError(f"Invalid mode '{mode}'. Use '{SANITIZE_MODE_TAGS_ONLY}' or '{SANITIZE_MODE_TAGS_ATTRS}'.")
