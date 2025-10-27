from src.render import render_page_source
from src.sanitize import tags_only_sanitizer, tags_attrs_sanitizer


def extract_sanitized_dom(url: str, mode: str = "tags_only", wait_seconds: int = 2, headless: bool = True):
    """
    Render URL -> Sanitize -> Return byte array ready for compression.
    """
    html = render_page_source(url, wait_seconds=wait_seconds, headless=headless)
    if not html:
        return None
    if mode == "tags_only":
        return tags_only_sanitizer(html)
    elif mode == "tags_attrs":
        return tags_attrs_sanitizer(html)
    else:
        raise ValueError("Invalid mode. Use 'tags_only' or 'tags_attrs'.")
