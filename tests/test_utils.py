"""Tests for utility functions."""
import pytest
from pathlib import Path
from src.utils import load_urls_from_file, ensure_dir


def test_load_urls_from_file(tmp_path):
    """Test loading URLs from file."""
    url_file = tmp_path / "test_urls.txt"
    url_file.write_text("https://example.com\nhttps://test.com\n# comment\n\nhttps://another.com")
    
    urls = load_urls_from_file(url_file)
    
    assert len(urls) == 3
    assert "https://example.com" in urls
    assert "https://test.com" in urls
    assert "https://another.com" in urls
    assert "# comment" not in urls


def test_load_urls_empty_file(tmp_path):
    """Test loading from empty file."""
    url_file = tmp_path / "empty.txt"
    url_file.write_text("")
    
    urls = load_urls_from_file(url_file)
    
    assert len(urls) == 0


def test_load_urls_nonexistent_file():
    """Test loading from non-existent file."""
    fake_file = Path("/nonexistent/file.txt")
    urls = load_urls_from_file(fake_file)
    
    assert len(urls) == 0


def test_load_urls_comments_only(tmp_path):
    """Test file with only comments."""
    url_file = tmp_path / "comments.txt"
    url_file.write_text("# comment 1\n# comment 2\n")
    
    urls = load_urls_from_file(url_file)
    
    assert len(urls) == 0


def test_ensure_dir_creates_directory(tmp_path):
    """Test directory creation."""
    new_dir = tmp_path / "new" / "nested" / "dir"
    
    ensure_dir(new_dir)
    
    assert new_dir.exists()
    assert new_dir.is_dir()


def test_ensure_dir_existing_directory(tmp_path):
    """Test with existing directory."""
    existing_dir = tmp_path / "existing"
    existing_dir.mkdir()
    
    # Should not raise error
    ensure_dir(existing_dir)
    
    assert existing_dir.exists()
