"""
Generate DOM samples from URL lists (urls-phish.txt and urls-legit.txt).
Processes URLs in parallel and saves sanitized DOM representations.
"""
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent directory to path for imports
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.extract_dom import extract_sanitized_dom
from src.save import save_dom_bytes
from src.utils import load_urls_from_file

OUTDIR = ROOT / "samples"
OUTDIR.mkdir(exist_ok=True)


def process_url(url: str, label: str, mode: str = "tags_only", 
                headless: bool = True, wait_seconds: int = 2):
    """
    Process a single URL: extract DOM, save to disk with metadata.
    
    Args:
        url: URL to process
        label: Classification label ('phish' or 'legit')
        mode: Sanitization mode
        headless: Run browser in headless mode
        wait_seconds: Seconds to wait for page load
        
    Returns:
        Tuple of (success: bool, url: str)
    """
    try:
        dom = extract_sanitized_dom(url, mode=mode, wait_seconds=wait_seconds, 
                                   headless=headless)
        if not dom:
            return False, url
        
        base, dom_path, meta_path = save_dom_bytes(url, dom, out_dir=str(OUTDIR))
        
        # Update metadata with label
        import json
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        meta["label"] = label
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        
        return True, url
    except Exception as e:
        print(f"[ERROR] Processing {url}: {e}")
        return False, url


def main():
    """Main entry point for sample generation."""
    phish_urls = load_urls_from_file(ROOT / "urls-phish.txt")
    legit_urls = load_urls_from_file(ROOT / "urls-legit.txt")
    
    print(f"Processing {len(phish_urls)} phishing URLs and {len(legit_urls)} legitimate URLs...")
    
    tasks = []
    with ThreadPoolExecutor(max_workers=3) as executor:
        # Submit phishing URLs
        for url in phish_urls:
            tasks.append(executor.submit(process_url, url, "phish"))
        
        # Submit legitimate URLs
        for url in legit_urls:
            tasks.append(executor.submit(process_url, url, "legit"))
        
        # Process results
        completed = 0
        failed = 0
        for future in as_completed(tasks):
            success, url = future.result()
            completed += 1
            if success:
                print(f"[{completed}/{len(tasks)}] ✓ {url}")
            else:
                failed += 1
                print(f"[{completed}/{len(tasks)}] ✗ {url}")
    
    print(f"\n{'='*60}")
    print(f"Completed: {completed - failed}/{len(tasks)}")
    print(f"Failed: {failed}/{len(tasks)}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
