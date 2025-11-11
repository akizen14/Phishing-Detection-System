"""Tests for detector module."""
import pytest
from pathlib import Path
from src.detector import load_dataset, classify_url


def test_load_dataset_empty_dir(tmp_path):
    """Test loading from empty directory."""
    dataset = load_dataset(tmp_path)
    assert isinstance(dataset, list)
    assert len(dataset) == 0


def test_load_dataset_nonexistent_dir():
    """Test loading from non-existent directory."""
    fake_path = Path("/nonexistent/directory")
    dataset = load_dataset(fake_path)
    assert isinstance(dataset, list)
    assert len(dataset) == 0


def test_classify_url_invalid_url():
    """Test classification with invalid URL."""
    dataset = []
    result = classify_url("not-a-valid-url", dataset)
    
    assert "error" in result
    assert result["classification"] == "error"


def test_classify_url_empty_dataset():
    """Test classification with empty dataset."""
    # This would require mocking extract_sanitized_dom
    # Placeholder for now
    pass


def test_classify_url_structure():
    """Test that classify_url returns expected structure."""
    # Mock test - would need proper mocking setup
    dataset = []
    result = classify_url("http://invalid-test-url.com", dataset)
    
    assert "url" in result
    assert "classification" in result
