"""Tests for HTML sanitization module."""
import pytest
from src.sanitize import tags_only_sanitizer, tags_attrs_sanitizer


def test_tags_only_basic():
    """Test basic tags-only sanitization."""
    html = "<html><body><div>Hello</div></body></html>"
    result = tags_only_sanitizer(html)
    
    assert isinstance(result, bytes)
    assert b"html" in result
    assert b"body" in result
    assert b"div" in result
    assert b"Hello" not in result  # Text should be removed


def test_tags_only_removes_scripts():
    """Test that scripts are removed."""
    html = """
    <html>
        <head><script>alert('test');</script></head>
        <body><div>Content</div></body>
    </html>
    """
    result = tags_only_sanitizer(html)
    
    assert b"script" not in result
    assert b"alert" not in result


def test_tags_only_removes_styles():
    """Test that styles are removed."""
    html = """
    <html>
        <head><style>.class { color: red; }</style></head>
        <body><div>Content</div></body>
    </html>
    """
    result = tags_only_sanitizer(html)
    
    assert b"style" not in result
    assert b"color" not in result


def test_tags_attrs_basic():
    """Test basic tags+attributes sanitization."""
    html = '<html><body><div id="main" class="container">Hello</div></body></html>'
    result = tags_attrs_sanitizer(html)
    
    assert isinstance(result, bytes)
    assert b"div:id" in result
    assert b"div:class" in result
    assert b"Hello" not in result  # Text should be removed


def test_tags_attrs_no_attributes():
    """Test tags without attributes."""
    html = "<html><body><div><p>Text</p></div></body></html>"
    result = tags_attrs_sanitizer(html)
    
    assert b"html" in result
    assert b"body" in result
    assert b"div" in result
    assert b"p" in result


def test_tags_attrs_removes_scripts():
    """Test that scripts are removed in tags+attrs mode."""
    html = """
    <html>
        <head><script src="test.js"></script></head>
        <body><div>Content</div></body>
    </html>
    """
    result = tags_attrs_sanitizer(html)
    
    assert b"script" not in result


def test_empty_html():
    """Test handling of empty HTML."""
    html = ""
    result = tags_only_sanitizer(html)
    
    assert isinstance(result, bytes)
    assert len(result) == 0
