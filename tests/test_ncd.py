"""Tests for NCD computation module."""
import pytest
from src.ncd import compress_size, NCDCache


def test_compress_size():
    """Test basic compression size calculation."""
    data = b"hello world"
    size = compress_size(data)
    assert isinstance(size, int)
    assert size > 0
    assert size < len(data)  # Compressed should be smaller for simple data


def test_compress_size_with_string():
    """Test compression with string input."""
    data = "test string"
    size = compress_size(data)
    assert isinstance(size, int)
    assert size > 0


def test_ncd_cache_csize():
    """Test NCDCache compressed size caching."""
    cache = NCDCache()
    data = b"test data"
    
    # First call
    size1 = cache.csize(data)
    assert isinstance(size1, int)
    
    # Second call should use cache
    size2 = cache.csize(data)
    assert size1 == size2


def test_ncd_identical():
    """Test NCD of identical data."""
    cache = NCDCache()
    data = b"identical data"
    
    ncd_value = cache.ncd(data, data)
    assert ncd_value == 0.0  # Identical data should have NCD of 0


def test_ncd_different():
    """Test NCD of different data."""
    cache = NCDCache()
    data1 = b"completely different string one"
    data2 = b"xyz abc 123"
    
    ncd_value = cache.ncd(data1, data2)
    assert 0.0 < ncd_value <= 1.0  # NCD should be between 0 and 1


def test_ncd_similar():
    """Test NCD of similar data."""
    cache = NCDCache()
    data1 = b"html head body div span"
    data2 = b"html head body div p"
    
    ncd_value = cache.ncd(data1, data2)
    assert 0.0 < ncd_value < 1.0
    assert ncd_value < 0.5  # Similar data should have low NCD
