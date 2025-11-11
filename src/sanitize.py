"""
HTML sanitization functions for DOM extraction.
"""
from bs4 import BeautifulSoup


def tags_only_sanitizer(html: str) -> bytes:
    """
    Keep only HTML tags and structure, remove text.
    """
    soup = BeautifulSoup(html, "html.parser")
    for script in soup(["script", "style", "noscript"]):
        script.extract()
    tags = " ".join([tag.name for tag in soup.find_all()])
    sanitized_dom_string = tags
    print("DOM LENGTH:", len(sanitized_dom_string))
    return tags.encode("utf-8")


def tags_attrs_sanitizer(html: str) -> bytes:
    """
    Keep HTML tag + attribute names (ignores text values).
    """
    soup = BeautifulSoup(html, "html.parser")
    for script in soup(["script", "style", "noscript"]):
        script.extract()
    pairs = []
    for tag in soup.find_all():
        if tag.attrs:
            pairs.extend([f"{tag.name}:{attr}" for attr in tag.attrs.keys()])
        else:
            pairs.append(tag.name)
    return " ".join(pairs).encode("utf-8")
