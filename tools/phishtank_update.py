"""
PhishTank dump downloader and local database updater.

This script downloads the PhishTank verified phishing URLs dump and
stores it in a local SQLite database for fast lookups.

Usage:
    python tools/phishtank_update.py [--dump-url URL] [--output PATH]

Schedule with cron (hourly update):
    0 * * * * cd /path/to/project && python tools/phishtank_update.py
"""
import os
import sys
import json
import sqlite3
import argparse
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict

import requests

# Add parent directory to path for imports
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.config import ROOT_DIR

# PhishTank dump URLs (verified phishing URLs only)
PHISHTANK_DUMP_URL = "http://data.phishtank.com/data/online-valid.json"
DEFAULT_DB_PATH = ROOT_DIR / "data" / "phishtank.db"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("phishtank_update")


def download_dump(dump_url: str = PHISHTANK_DUMP_URL) -> List[Dict]:
    """
    Download PhishTank dump JSON.
    
    Args:
        dump_url: URL to PhishTank dump
        
    Returns:
        List of phishing entries
    """
    logger.info(f"Downloading PhishTank dump from {dump_url}")
    
    headers = {
        "User-Agent": "phishing-ncd-detector/2.0 (+https://github.com/yourusername/phishing-ncd-detector)"
    }
    
    try:
        resp = requests.get(dump_url, headers=headers, timeout=60)
        resp.raise_for_status()
        
        data = resp.json()
        logger.info(f"Downloaded {len(data)} phishing entries")
        return data
    except Exception as e:
        logger.error(f"Failed to download PhishTank dump: {e}")
        raise


def create_database(db_path: Path):
    """
    Create SQLite database with phishtank table.
    
    Args:
        db_path: Path to database file
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    # Create table with indexes for fast lookups
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS phishtank (
            phish_id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            verified INTEGER NOT NULL,
            submission_time TEXT,
            detail_url TEXT,
            target TEXT,
            updated_at TEXT NOT NULL
        )
    """)
    
    # Create index on URL for fast lookups
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_url ON phishtank(url)
    """)
    
    # Create metadata table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    
    conn.commit()
    conn.close()
    logger.info(f"Database created at {db_path}")


def update_database(db_path: Path, entries: List[Dict]):
    """
    Update database with new phishing entries.
    
    Args:
        db_path: Path to database file
        entries: List of phishing entry dicts
    """
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    # Clear existing data
    cursor.execute("DELETE FROM phishtank")
    
    # Insert new entries
    now = datetime.utcnow().isoformat()
    inserted = 0
    
    for entry in entries:
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO phishtank 
                (phish_id, url, verified, submission_time, detail_url, target, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                entry.get("phish_id"),
                entry.get("url"),
                1 if entry.get("verified") == "yes" else 0,
                entry.get("submission_time"),
                entry.get("phish_detail_url"),
                entry.get("target"),
                now
            ))
            inserted += 1
        except Exception as e:
            logger.warning(f"Failed to insert entry {entry.get('phish_id')}: {e}")
    
    # Update metadata
    cursor.execute("""
        INSERT OR REPLACE INTO metadata (key, value) VALUES ('last_updated', ?)
    """, (now,))
    
    cursor.execute("""
        INSERT OR REPLACE INTO metadata (key, value) VALUES ('entry_count', ?)
    """, (str(inserted),))
    
    conn.commit()
    conn.close()
    
    logger.info(f"Database updated with {inserted} entries")


def get_database_info(db_path: Path) -> Dict:
    """
    Get information about the database.
    
    Args:
        db_path: Path to database file
        
    Returns:
        Dict with database info
    """
    if not db_path.exists():
        return {"exists": False}
    
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    # Get entry count
    cursor.execute("SELECT COUNT(*) FROM phishtank")
    count = cursor.fetchone()[0]
    
    # Get last updated
    cursor.execute("SELECT value FROM metadata WHERE key = 'last_updated'")
    row = cursor.fetchone()
    last_updated = row[0] if row else "unknown"
    
    conn.close()
    
    return {
        "exists": True,
        "path": str(db_path),
        "entry_count": count,
        "last_updated": last_updated
    }


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Download and update PhishTank local database"
    )
    parser.add_argument(
        "--dump-url",
        default=PHISHTANK_DUMP_URL,
        help="URL to PhishTank dump (default: online-valid.json)"
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_DB_PATH),
        help=f"Output database path (default: {DEFAULT_DB_PATH})"
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Show database info and exit"
    )
    
    args = parser.parse_args()
    db_path = Path(args.output)
    
    if args.info:
        info = get_database_info(db_path)
        print(json.dumps(info, indent=2))
        return
    
    try:
        # Download dump
        entries = download_dump(args.dump_url)
        
        # Create/update database
        create_database(db_path)
        update_database(db_path, entries)
        
        # Show info
        info = get_database_info(db_path)
        logger.info(f"Update complete: {info['entry_count']} entries")
        print(json.dumps(info, indent=2))
        
    except Exception as e:
        logger.error(f"Update failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
