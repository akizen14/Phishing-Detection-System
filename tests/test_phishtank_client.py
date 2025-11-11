"""Tests for PhishTank client module."""
import pytest
from unittest.mock import patch, MagicMock
from src.phishtank_client import (
    phishtank_lookup,
    get_metrics,
    reset_metrics,
    clear_cache,
    _check_local_db,
    _post_lookup
)


@pytest.fixture(autouse=True)
def reset_test_state():
    """Reset metrics and cache before each test."""
    reset_metrics()
    clear_cache()
    yield
    reset_metrics()
    clear_cache()


@pytest.fixture
def mock_phishtank_verified_response():
    """Mock response for verified phishing URL."""
    return {
        "results": {
            "in_database": True,
            "verified": True,
            "phish_id": 12345,
            "url": "http://phishing-site.com",
            "phish_detail_page": "https://phishtank.com/phish_detail.php?phish_id=12345",
            "submission_time": "2024-01-01T12:00:00+00:00"
        }
    }


@pytest.fixture
def mock_phishtank_unverified_response():
    """Mock response for unverified phishing URL."""
    return {
        "results": {
            "in_database": True,
            "verified": False,
            "phish_id": 67890,
            "url": "http://suspicious-site.com",
            "phish_detail_page": "https://phishtank.com/phish_detail.php?phish_id=67890",
            "submission_time": "2024-01-01T12:00:00+00:00"
        }
    }


@pytest.fixture
def mock_phishtank_not_found_response():
    """Mock response for URL not in database."""
    return {
        "results": {
            "in_database": False,
            "verified": False,
            "url": "http://legitimate-site.com"
        }
    }


class TestPhishTankLookup:
    """Test PhishTank lookup functionality."""
    
    @patch('src.phishtank_client._post_lookup')
    def test_lookup_verified_phish(self, mock_post, mock_phishtank_verified_response):
        """Test lookup of verified phishing URL."""
        mock_post.return_value = mock_phishtank_verified_response
        
        result = phishtank_lookup("http://phishing-site.com")
        
        assert result["in_database"] is True
        assert result["verified"] is True
        assert result["phish_id"] == 12345
        assert result["source"] == "api"
        assert result["error"] is None
        
        # Check metrics
        metrics = get_metrics()
        assert metrics["lookup_count"] == 1
        assert metrics["hits"] == 1
        assert metrics["errors"] == 0
    
    @patch('src.phishtank_client._post_lookup')
    def test_lookup_unverified_phish(self, mock_post, mock_phishtank_unverified_response):
        """Test lookup of unverified phishing URL."""
        mock_post.return_value = mock_phishtank_unverified_response
        
        result = phishtank_lookup("http://suspicious-site.com")
        
        assert result["in_database"] is True
        assert result["verified"] is False
        assert result["phish_id"] == 67890
        assert result["source"] == "api"
        
        # Should not count as hit if not verified
        metrics = get_metrics()
        assert metrics["hits"] == 0
    
    @patch('src.phishtank_client._post_lookup')
    def test_lookup_not_in_database(self, mock_post, mock_phishtank_not_found_response):
        """Test lookup of URL not in PhishTank database."""
        mock_post.return_value = mock_phishtank_not_found_response
        
        result = phishtank_lookup("http://legitimate-site.com")
        
        assert result["in_database"] is False
        assert result["verified"] is False
        assert result["phish_id"] is None
        assert result["source"] == "api"
    
    @patch('src.phishtank_client._post_lookup')
    def test_lookup_network_error(self, mock_post):
        """Test handling of network errors."""
        mock_post.side_effect = Exception("Network error")
        
        result = phishtank_lookup("http://test-site.com")
        
        assert result["in_database"] is False
        assert result["verified"] is False
        assert result["source"] == "error"
        assert "Network error" in result["error"]
        
        # Check error metric
        metrics = get_metrics()
        assert metrics["errors"] == 1
    
    def test_skip_signature_flag(self):
        """Test skip_signature parameter."""
        result = phishtank_lookup("http://test.com", skip_signature=True)
        
        assert result["in_database"] is False
        assert result["verified"] is False
        assert result["source"] == "skipped"
        assert result["error"] is None
    
    @patch('src.phishtank_client._post_lookup')
    def test_caching_behavior(self, mock_post, mock_phishtank_verified_response):
        """Test that results are cached."""
        mock_post.return_value = mock_phishtank_verified_response
        
        url = "http://cached-test.com"
        
        # First call
        result1 = phishtank_lookup(url)
        assert mock_post.call_count == 1
        
        # Second call should use cache
        result2 = phishtank_lookup(url)
        assert mock_post.call_count == 1  # Still 1, not called again
        
        # Results should be identical
        assert result1 == result2
        
        # Check cache hit metric
        metrics = get_metrics()
        assert metrics["cache_hits"] == 1


class TestPostLookup:
    """Test low-level POST functionality."""
    
    @patch('src.phishtank_client.requests.post')
    def test_post_lookup_success(self, mock_post):
        """Test successful POST request."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"results": {"in_database": False}}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response
        
        result = _post_lookup("http://test.com")
        
        assert result == {"results": {"in_database": False}}
        assert mock_post.call_count == 1
    
    @patch('src.phishtank_client.requests.post')
    def test_post_lookup_retry_logic(self, mock_post):
        """Test retry logic on failures."""
        # First two calls fail, third succeeds
        mock_post.side_effect = [
            Exception("Timeout"),
            Exception("Timeout"),
            MagicMock(json=lambda: {"results": {}}, raise_for_status=lambda: None)
        ]
        
        result = _post_lookup("http://test.com", retry_count=3)
        
        assert result == {"results": {}}
        assert mock_post.call_count == 3
    
    @patch('src.phishtank_client.requests.post')
    def test_post_lookup_all_retries_fail(self, mock_post):
        """Test when all retries fail."""
        mock_post.side_effect = Exception("Network error")
        
        with pytest.raises(Exception, match="Network error"):
            _post_lookup("http://test.com", retry_count=2)
        
        assert mock_post.call_count == 2


class TestLocalDatabase:
    """Test local database functionality."""
    
    @patch('src.phishtank_client.USE_LOCAL_DUMP', True)
    @patch('src.phishtank_client.sqlite3.connect')
    def test_check_local_db_found(self, mock_connect):
        """Test local DB lookup when URL is found."""
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (
            12345,  # phish_id
            "http://phish.com",  # url
            1,  # verified
            "2024-01-01",  # submission_time
            "https://phishtank.com/detail/12345"  # detail_url
        )
        
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        
        result = _check_local_db("http://phish.com")
        
        assert result is not None
        assert result["in_database"] is True
        assert result["verified"] is True
        assert result["phish_id"] == 12345
        assert result["source"] == "local_db"
    
    @patch('src.phishtank_client.USE_LOCAL_DUMP', True)
    @patch('src.phishtank_client.sqlite3.connect')
    def test_check_local_db_not_found(self, mock_connect):
        """Test local DB lookup when URL is not found."""
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        
        result = _check_local_db("http://legit.com")
        
        assert result is None
    
    @patch('src.phishtank_client.USE_LOCAL_DUMP', False)
    def test_check_local_db_disabled(self):
        """Test that local DB is not checked when disabled."""
        result = _check_local_db("http://test.com")
        assert result is None


class TestMetrics:
    """Test metrics functionality."""
    
    def test_metrics_initial_state(self):
        """Test initial metrics state."""
        metrics = get_metrics()
        
        assert metrics["lookup_count"] == 0
        assert metrics["hits"] == 0
        assert metrics["errors"] == 0
        assert metrics["cache_hits"] == 0
        assert metrics["local_db_hits"] == 0
    
    @patch('src.phishtank_client._post_lookup')
    def test_metrics_increment(self, mock_post, mock_phishtank_verified_response):
        """Test that metrics increment correctly."""
        mock_post.return_value = mock_phishtank_verified_response
        
        # Perform lookups
        phishtank_lookup("http://test1.com")
        phishtank_lookup("http://test2.com")
        phishtank_lookup("http://test1.com")  # Cache hit
        
        metrics = get_metrics()
        assert metrics["lookup_count"] == 3
        assert metrics["hits"] == 2  # Only first two are actual hits
        assert metrics["cache_hits"] == 1
    
    def test_reset_metrics(self):
        """Test metrics reset."""
        # Manually increment metrics
        from src.phishtank_client import _metrics
        _metrics["lookup_count"] = 10
        _metrics["hits"] = 5
        
        reset_metrics()
        
        metrics = get_metrics()
        assert metrics["lookup_count"] == 0
        assert metrics["hits"] == 0


class TestCacheManagement:
    """Test cache management."""
    
    @patch('src.phishtank_client._post_lookup')
    def test_clear_cache(self, mock_post, mock_phishtank_verified_response):
        """Test cache clearing."""
        mock_post.return_value = mock_phishtank_verified_response
        
        url = "http://test.com"
        
        # First lookup
        phishtank_lookup(url)
        assert mock_post.call_count == 1
        
        # Second lookup uses cache
        phishtank_lookup(url)
        assert mock_post.call_count == 1
        
        # Clear cache
        clear_cache()
        
        # Third lookup should call API again
        phishtank_lookup(url)
        assert mock_post.call_count == 2
