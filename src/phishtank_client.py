"""
PhishTank signature-based lookup client using local SQLite database.
No API calls needed - instant lookups from local database.
"""
import os
import logging
import sqlite3
from typing import Dict, Optional
from pathlib import Path

from cachetools import TTLCache, cached

from src.config import ROOT_DIR

# PhishTank local database configuration
CACHE_TTL = int(os.getenv("PHISHTANK_CACHE_TTL", "3600"))
DB_PATH = os.getenv("PHISHTANK_DB_PATH", str(ROOT_DIR / "src" / "db_phishtank.sqlite"))

logger = logging.getLogger("phishtank_client")

# In-memory TTL cache for API lookups
_cache = TTLCache(maxsize=10000, ttl=CACHE_TTL)

# Metrics counters
_metrics = {
    "lookup_count": 0,
    "hits": 0,
    "errors": 0,
    "cache_hits": 0,
    "db_hits": 0,
}


def get_metrics() -> Dict:
    """Return current PhishTank metrics."""
    return _metrics.copy()


def reset_metrics():
    """Reset all metrics counters."""
    global _metrics
    _metrics = {
        "lookup_count": 0,
        "hits": 0,
        "errors": 0,
        "cache_hits": 0,
        "db_hits": 0,
    }


def _check_local_db(url: str) -> Optional[Dict]:
    """
    Check local SQLite database for URL.
    
    Args:
        url: URL to lookup
        
    Returns:
        Dict with phishing info if found, None otherwise
    """
    db_path = Path(DB_PATH)
    if not db_path.exists():
        logger.warning(f"PhishTank database not found at {DB_PATH}")
        logger.warning("Run: python tools/phishtank_update_local.py")
        return None
    
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # Query for exact URL match
        cursor.execute(
            "SELECT phish_id, url, submission_time, target FROM phishtank_urls WHERE url = ? LIMIT 1",
            (url,)
        )
        row = cursor.fetchone()
        conn.close()
        
        if row:
            _metrics["db_hits"] += 1
            phish_id = row[0]
            return {
                "in_database": True,
                "verified": True,  # All entries in local DB are verified
                "phish_id": phish_id,
                "url": row[1],
                "detail_page": f"https://phishtank.com/phish_detail.php?phish_id={phish_id}",
                "submitted_at": row[2],
                "target": row[3],
                "source": "phishtank-local",
                "error": None
            }
        
        return None
    except Exception as e:
        logger.error(f"Error querying PhishTank database: {e}")
        return None




@cached(_cache)
def phishtank_lookup(url: str, skip_signature: bool = False) -> Dict:
    """
    Lookup URL in local PhishTank database (no API calls).
    
    Returns standardized dict:
    {
      "in_database": bool,
      "verified": bool,
      "phish_id": Optional[int],
      "url": str,
      "detail_page": Optional[str],
      "submitted_at": Optional[str],
      "source": str,  # "phishtank-local" or "error"
      "error": Optional[str]
    }
    
    Args:
        url: URL to check
        skip_signature: If True, skip lookup and return not found
        
    Returns:
        Lookup result dictionary
    """
    _metrics["lookup_count"] += 1
    
    if skip_signature:
        return {
            "in_database": False,
            "verified": False,
            "phish_id": None,
            "url": url,
            "detail_page": None,
            "submitted_at": None,
            "source": "skipped",
            "error": None
        }
    
    # Check if this is a cached result
    cache_key = url
    if cache_key in _cache:
        _metrics["cache_hits"] += 1
    
    # Check local database
    local_result = _check_local_db(url)
    if local_result:
        if local_result["verified"]:
            _metrics["hits"] += 1
        return local_result
    
    # Not found in database
    return {
        "in_database": False,
        "verified": False,
        "phish_id": None,
        "url": url,
        "detail_page": None,
        "submitted_at": None,
        "source": "phishtank-local",
        "error": None
    }


def clear_cache():
    """Clear the in-memory lookup cache."""
    _cache.clear()
    logger.info("PhishTank cache cleared")
