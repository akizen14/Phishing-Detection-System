"""
Legitimate Sample Collection Script

Collects DOM samples from known legitimate websites to improve
NCD classification accuracy.

Usage:
    python tools/collect_legit_samples.py
"""
import sys
import time
import logging
from pathlib import Path
from urllib.parse import urlparse

# Add parent directory to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.extract_dom import extract_sanitized_dom
from src.config import ROOT_DIR

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Output directory
LEGIT_DIR = ROOT_DIR / "samples" / "legit"

# List of known legitimate URLs to collect
LEGIT_URLS = [
    "https://www.google.com/",
    "https://www.facebook.com/",
    "https://www.twitter.com/",
    "https://github.com/",
    "https://www.paypal.com/",
    "https://www.apple.com/",
    "https://www.microsoft.com/",
    "https://www.yahoo.com/",
    "https://www.linkedin.com/",
    "https://www.amazon.com/",
    "https://www.wikipedia.org/",
    "https://www.reddit.com/",
    "https://www.netflix.com/",
    "https://www.instagram.com/",
    "https://www.youtube.com/",
]


def normalize_filename(url: str) -> str:
    """
    Convert URL to a normalized filename.
    
    Args:
        url: URL to normalize
        
    Returns:
        Normalized filename (without extension)
    """
    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "")
    path = parsed.path.strip("/").replace("/", "_")
    
    if path:
        filename = f"{domain}_{path}".replace(".", "_")
    else:
        filename = domain.replace(".", "_")
    
    # Clean up filename
    filename = "".join(c if c.isalnum() or c == "_" else "_" for c in filename)
    return filename


def collect_sample(url: str, output_dir: Path) -> bool:
    """
    Collect a single legitimate sample.
    
    Args:
        url: URL to collect
        output_dir: Directory to save the sample
        
    Returns:
        True if successful, False otherwise
    """
    logger.info(f"Collecting: {url}")
    
    try:
        # Extract and sanitize DOM
        dom_bytes = extract_sanitized_dom(url, wait_seconds=3, headless=True)
        
        if not dom_bytes:
            logger.warning(f"Failed to extract DOM from {url}")
            return False
        
        # Generate filename
        filename = normalize_filename(url)
        output_path = output_dir / f"{filename}.dom"
        
        # Save to file
        with open(output_path, "wb") as f:
            f.write(dom_bytes)
        
        logger.info(f"✓ Saved: {output_path.name} ({len(dom_bytes)} bytes)")
        return True
        
    except Exception as e:
        logger.error(f"Error collecting {url}: {e}")
        return False


def main():
    """Main entry point."""
    print("=" * 70)
    print("Legitimate Sample Collection")
    print("=" * 70)
    print()
    
    # Ensure output directory exists
    LEGIT_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"Output directory: {LEGIT_DIR}")
    
    # Check existing samples
    existing = list(LEGIT_DIR.glob("*.dom"))
    logger.info(f"Existing samples: {len(existing)}")
    print()
    
    # Collect samples
    logger.info(f"Collecting {len(LEGIT_URLS)} legitimate samples...")
    logger.info("This may take several minutes...")
    print()
    
    success_count = 0
    fail_count = 0
    
    for i, url in enumerate(LEGIT_URLS, 1):
        print(f"[{i}/{len(LEGIT_URLS)}] Processing: {url}")
        
        if collect_sample(url, LEGIT_DIR):
            success_count += 1
        else:
            fail_count += 1
        
        # Small delay between requests to be respectful
        if i < len(LEGIT_URLS):
            time.sleep(2)
        
        print()
    
    # Summary
    print("=" * 70)
    print("COLLECTION SUMMARY")
    print("=" * 70)
    print(f"Successfully collected: {success_count}")
    print(f"Failed: {fail_count}")
    print(f"Total samples in {LEGIT_DIR}: {len(list(LEGIT_DIR.glob('*.dom')))}")
    print()
    
    if success_count >= 10:
        print("✓ SUCCESS: Collected at least 10 legitimate samples")
        print()
        print("Next steps:")
        print("  1. Run: python tools/tune_threshold.py")
        print("  2. Review updated threshold recommendations")
    else:
        print("⚠ WARNING: Collected fewer than 10 samples")
        print("  Consider adding more URLs or checking ChromeDriver setup")
    
    print("=" * 70)


if __name__ == "__main__":
    main()
