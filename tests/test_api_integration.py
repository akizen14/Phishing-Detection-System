"""Integration tests for API with PhishTank."""
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from src.api import app


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def mock_phishtank_verified():
    """Mock PhishTank verified phishing result."""
    return {
        "in_database": True,
        "verified": True,
        "phish_id": 12345,
        "url": "http://phishing-site.com",
        "detail_page": "https://phishtank.com/phish_detail.php?phish_id=12345",
        "submitted_at": "2024-01-01T12:00:00+00:00",
        "source": "api",
        "error": None,
        "raw": {}
    }


@pytest.fixture
def mock_phishtank_not_found():
    """Mock PhishTank not found result."""
    return {
        "in_database": False,
        "verified": False,
        "phish_id": None,
        "url": "http://legitimate-site.com",
        "detail_page": None,
        "submitted_at": None,
        "source": "api",
        "error": None,
        "raw": {}
    }


@pytest.fixture
def mock_phishtank_error():
    """Mock PhishTank error result."""
    return {
        "in_database": False,
        "verified": False,
        "phish_id": None,
        "url": "http://test.com",
        "detail_page": None,
        "submitted_at": None,
        "source": "error",
        "error": "Network timeout",
        "raw": None
    }


class TestDetectEndpoint:
    """Test /detect endpoint with PhishTank integration."""
    
    @patch('src.api.phishtank_lookup')
    def test_detect_phishtank_verified_hit(self, mock_lookup, client, mock_phishtank_verified):
        """Test detection short-circuits on verified PhishTank hit."""
        mock_lookup.return_value = mock_phishtank_verified
        
        response = client.get("/detect?url=http://phishing-site.com")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["classification"] == "phish"
        assert data["source"] == "phishtank"
        assert data["confidence"] == "high"
        assert data["phish_id"] == 12345
        assert "detail_page" in data
        
        # Verify PhishTank was called
        mock_lookup.assert_called_once()
    
    @patch('src.api.phishtank_lookup')
    @patch('src.api.classify_url')
    def test_detect_phishtank_not_found_fallback(
        self, mock_classify, mock_lookup, client, mock_phishtank_not_found
    ):
        """Test fallback to NCD when not in PhishTank."""
        mock_lookup.return_value = mock_phishtank_not_found
        mock_classify.return_value = {
            "url": "http://legitimate-site.com",
            "ncd": 0.45,
            "classification": "legit",
            "closest_sample": "http://example.com"
        }
        
        response = client.get("/detect?url=http://legitimate-site.com")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["source"] == "ncd"
        assert data["classification"] == "legit"
        assert "ncd" in data
        
        # Verify both PhishTank and NCD were called
        mock_lookup.assert_called_once()
        mock_classify.assert_called_once()
    
    @patch('src.api.phishtank_lookup')
    @patch('src.api.classify_url')
    def test_detect_phishtank_error_fallback(
        self, mock_classify, mock_lookup, client, mock_phishtank_error
    ):
        """Test fallback to NCD on PhishTank error (fail-open)."""
        mock_lookup.return_value = mock_phishtank_error
        mock_classify.return_value = {
            "url": "http://test.com",
            "ncd": 0.15,
            "classification": "phish",
            "closest_sample": "http://known-phish.com"
        }
        
        response = client.get("/detect?url=http://test.com")
        
        assert response.status_code == 200
        data = response.json()
        
        # Should fall back to NCD
        assert data["source"] == "ncd"
        assert "ncd" in data
        
        mock_classify.assert_called_once()
    
    @patch('src.api.phishtank_lookup')
    def test_detect_skip_signature_param(self, mock_lookup, client):
        """Test skip_signature parameter bypasses PhishTank."""
        response = client.get("/detect?url=http://test.com&skip_signature=true")
        
        assert response.status_code == 200
        
        # PhishTank should not be called
        mock_lookup.assert_not_called()
    
    @patch('src.api.phishtank_lookup')
    @patch('src.api.classify_url')
    def test_detect_unverified_phish(self, mock_classify, mock_lookup, client):
        """Test handling of unverified PhishTank entries."""
        mock_lookup.return_value = {
            "in_database": True,
            "verified": False,
            "phish_id": 67890,
            "url": "http://suspicious.com",
            "detail_page": "https://phishtank.com/phish_detail.php?phish_id=67890",
            "submitted_at": "2024-01-01",
            "source": "api",
            "error": None,
            "raw": {}
        }
        mock_classify.return_value = {
            "url": "http://suspicious.com",
            "ncd": 0.20,
            "classification": "phish",
            "closest_sample": "http://known-phish.com"
        }
        
        response = client.get("/detect?url=http://suspicious.com")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["classification"] == "suspicious"
        assert data["source"] == "phishtank_unverified"
        assert data["confidence"] == "medium"
        assert "ncd_result" in data
        
        # Both PhishTank and NCD should be called
        mock_lookup.assert_called_once()
        mock_classify.assert_called_once()


class TestMetricsEndpoint:
    """Test /metrics endpoint."""
    
    @patch('src.api.get_phishtank_metrics')
    def test_metrics_endpoint(self, mock_metrics, client):
        """Test metrics endpoint returns PhishTank stats."""
        mock_metrics.return_value = {
            "lookup_count": 100,
            "hits": 25,
            "errors": 5,
            "cache_hits": 50,
            "local_db_hits": 10
        }
        
        response = client.get("/metrics")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "phishtank" in data
        assert data["phishtank"]["lookup_count"] == 100
        assert data["phishtank"]["hits"] == 25
        
        assert "ncd" in data
        assert "samples_loaded" in data["ncd"]


class TestEndpointDocumentation:
    """Test API documentation includes PhishTank info."""
    
    def test_openapi_schema(self, client):
        """Test OpenAPI schema includes new parameters."""
        response = client.get("/openapi.json")
        
        assert response.status_code == 200
        schema = response.json()
        
        # Check /detect endpoint has skip_signature parameter
        detect_params = schema["paths"]["/detect"]["get"]["parameters"]
        param_names = [p["name"] for p in detect_params]
        
        assert "skip_signature" in param_names
