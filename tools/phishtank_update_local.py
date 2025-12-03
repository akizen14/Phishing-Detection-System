"""
PhishTank Local Database Updater

Downloads the PhishTank verified phishing dataset (CSV) and builds a local SQLite database
for instant lookups without API calls.

Usage:
    python tools/phishtank_update_local.py
    
Schedule with cron (daily update):
    0 2 * * * cd /path/to/project && python tools/phishtank_update_local.py
"""
import os
import sys
import csv
import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from io import StringIO

import requests

# Add parent directory to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.config import ROOT_DIR

# PhishTank CSV dump URL (verified phishing URLs only)
PHISHTANK_CSV_URL = "https://data.phishtank.com/data/online-valid.csv"
DEFAULT_DB_PATH = ROOT_DIR / "src" / "db_phishtank.sqlite"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def download_phishtank_csv(url: str = PHISHTANK_CSV_URL) -> str:
    """
    Download PhishTank CSV dump.
    
    Args:
        url: URL to PhishTank CSV dump
        
    Returns:
        CSV content as string
    """
    logger.info(f"Downloading PhishTank CSV from {url}")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/csv,application/json,*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://www.phishtank.com/"
    }
    
    try:
        # Add a small delay to avoid rate limiting
        import time
        time.sleep(2)
        
        response = requests.get(url, headers=headers, timeout=120)
        response.raise_for_status()
        
        csv_content = response.text
        logger.info(f"Downloaded {len(csv_content)} bytes")
        return csv_content
        
    except Exception as e:
        logger.error(f"Failed to download PhishTank CSV: {e}")
        raise


def parse_csv_content(csv_content: str) -> list:
    """
    Parse PhishTank CSV content.
    
    CSV format:
    phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target
    
    Args:
        csv_content: CSV content as string
        
    Returns:
        List of dictionaries with phishing data
    """
    logger.info("Parsing CSV content")
    
    entries = []
    csv_file = StringIO(csv_content)
    reader = csv.DictReader(csv_file)
    
    for row in reader:
        # Only include verified entries
        if row.get('verified') == 'yes' and row.get('online') == 'yes':
            entries.append({
                'phish_id': int(row['phish_id']),
                'url': row['url'],
                'submission_time': row.get('submission_time', ''),
                'target': row.get('target', '')
            })
    
    logger.info(f"Parsed {len(entries)} verified phishing URLs")
    return entries


def create_database(db_path: Path):
    """
    Create SQLite database with phishtank_urls table.
    
    Args:
        db_path: Path to database file
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    # Drop existing table if it exists
    cursor.execute("DROP TABLE IF EXISTS phishtank_urls")
    
    # Create table
    cursor.execute("""
        CREATE TABLE phishtank_urls (
            phish_id INTEGER PRIMARY KEY,
            url TEXT UNIQUE NOT NULL,
            submission_time TEXT,
            target TEXT,
            updated_at TEXT NOT NULL
        )
    """)
    
    # Create index on URL for fast lookups
    cursor.execute("""
        CREATE INDEX idx_url ON phishtank_urls(url)
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


def insert_entries(db_path: Path, entries: list):
    """
    Insert phishing entries into database.
    
    Args:
        db_path: Path to database file
        entries: List of phishing entry dictionaries
    """
    logger.info(f"Inserting {len(entries)} entries into database")
    
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    now = datetime.utcnow().isoformat()
    inserted = 0
    
    for entry in entries:
        try:
            cursor.execute("""
                INSERT OR REPLACE INTO phishtank_urls 
                (phish_id, url, submission_time, target, updated_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                entry['phish_id'],
                entry['url'],
                entry['submission_time'],
                entry['target'],
                now
            ))
            inserted += 1
        except Exception as e:
            logger.warning(f"Failed to insert entry {entry['phish_id']}: {e}")
    
    # Update metadata
    cursor.execute("""
        INSERT OR REPLACE INTO metadata (key, value) 
        VALUES ('last_updated', ?)
    """, (now,))
    
    cursor.execute("""
        INSERT OR REPLACE INTO metadata (key, value) 
        VALUES ('entry_count', ?)
    """, (str(inserted),))
    
    conn.commit()
    conn.close()
    
    logger.info(f"Successfully inserted {inserted} entries")


def get_database_info(db_path: Path) -> dict:
    """
    Get information about the database.
    
    Args:
        db_path: Path to database file
        
    Returns:
        Dictionary with database info
    """
    if not db_path.exists():
        return {"exists": False}
    
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    # Get entry count
    cursor.execute("SELECT COUNT(*) FROM phishtank_urls")
    count = cursor.fetchone()[0]
    
    # Get last updated
    cursor.execute("SELECT value FROM metadata WHERE key = 'last_updated'")
    row = cursor.fetchone()
    last_updated = row[0] if row else "unknown"
    
    # Get database size
    db_size = db_path.stat().st_size
    
    conn.close()
    
    return {
        "exists": True,
        "path": str(db_path),
        "entry_count": count,
        "last_updated": last_updated,
        "size_mb": round(db_size / (1024 * 1024), 2)
    }


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Update local PhishTank database"
    )
    parser.add_argument(
        "--db-path",
        default=str(DEFAULT_DB_PATH),
        help=f"Database path (default: {DEFAULT_DB_PATH})"
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Show database info and exit"
    )
    
    args = parser.parse_args()
    db_path = Path(args.db_path)
    
    if args.info:
        info = get_database_info(db_path)
        print("\n" + "="*60)
        print("PhishTank Local Database Info")
        print("="*60)
        if info["exists"]:
            print(f"Path: {info['path']}")
            print(f"Entries: {info['entry_count']:,}")
            print(f"Last Updated: {info['last_updated']}")
            print(f"Size: {info['size_mb']} MB")
        else:
            print("Database does not exist. Run without --info to create it.")
        print("="*60 + "\n")
        return
    
    try:
        logger.info("Starting PhishTank database update")
        
        # Download CSV
        csv_content = download_phishtank_csv()
        
        # Parse entries
        entries = parse_csv_content(csv_content)
        
        if not entries:
            logger.error("No entries found in CSV. Aborting.")
            sys.exit(1)
        
        # Create database
        create_database(db_path)
        
        # Insert entries
        insert_entries(db_path, entries)
        
        # Show info
        info = get_database_info(db_path)
        logger.info("="*60)
        logger.info("Update Complete!")
        logger.info(f"Database: {info['path']}")
        logger.info(f"Entries: {info['entry_count']:,}")
        logger.info(f"Size: {info['size_mb']} MB")
        logger.info("="*60)
        
    except Exception as e:
        logger.error(f"Update failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
