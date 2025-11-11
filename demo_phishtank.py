"""
Demo script to test PhishTank integration.

This script demonstrates:
1. API-based lookup
2. Local database lookup (if configured)
3. Caching behavior
4. Metrics collection
"""
import sys
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from src.phishtank_client import (
    phishtank_lookup,
    get_metrics,
    reset_metrics,
    clear_cache
)


def demo_api_lookup():
    """Demonstrate API-based lookup."""
    print("=" * 60)
    print("DEMO 1: API-Based Lookup")
    print("=" * 60)
    
    # Known phishing URLs (examples - may not be in current database)
    test_urls = [
        "http://paypal-secure-login.com",
        "http://google.com",
        "http://facebook.com"
    ]
    
    for url in test_urls:
        print(f"\nLooking up: {url}")
        result = phishtank_lookup(url)
        
        print(f"  In Database: {result['in_database']}")
        print(f"  Verified: {result['verified']}")
        print(f"  Source: {result['source']}")
        
        if result['phish_id']:
            print(f"  Phish ID: {result['phish_id']}")
            print(f"  Detail: {result['detail_page']}")
    
    # Show metrics
    print("\n" + "-" * 60)
    print("Metrics:")
    metrics = get_metrics()
    for key, value in metrics.items():
        print(f"  {key}: {value}")


def demo_caching():
    """Demonstrate caching behavior."""
    print("\n" + "=" * 60)
    print("DEMO 2: Caching Behavior")
    print("=" * 60)
    
    reset_metrics()
    clear_cache()
    
    url = "http://example.com"
    
    print(f"\nFirst lookup (should hit API): {url}")
    result1 = phishtank_lookup(url)
    metrics1 = get_metrics()
    print(f"  Lookup count: {metrics1['lookup_count']}")
    print(f"  Cache hits: {metrics1['cache_hits']}")
    
    print(f"\nSecond lookup (should use cache): {url}")
    result2 = phishtank_lookup(url)
    metrics2 = get_metrics()
    print(f"  Lookup count: {metrics2['lookup_count']}")
    print(f"  Cache hits: {metrics2['cache_hits']}")
    
    print("\n✓ Cache is working!" if metrics2['cache_hits'] > 0 else "\n✗ Cache not working")


def demo_skip_signature():
    """Demonstrate skip_signature parameter."""
    print("\n" + "=" * 60)
    print("DEMO 3: Skip Signature Flag")
    print("=" * 60)
    
    url = "http://test.com"
    
    print(f"\nLookup with skip_signature=True: {url}")
    result = phishtank_lookup(url, skip_signature=True)
    
    print(f"  Source: {result['source']}")
    print(f"  In Database: {result['in_database']}")
    
    if result['source'] == 'skipped':
        print("\n✓ Signature lookup was skipped as expected")


def demo_local_db():
    """Demonstrate local database lookup."""
    print("\n" + "=" * 60)
    print("DEMO 4: Local Database Mode")
    print("=" * 60)
    
    import os
    use_local = os.getenv("PHISHTANK_USE_LOCAL_DUMP", "false").lower() == "true"
    db_path = os.getenv("PHISHTANK_DUMP_PATH", "data/phishtank.db")
    
    print(f"\nLocal dump enabled: {use_local}")
    print(f"Database path: {db_path}")
    
    if use_local:
        from pathlib import Path
        if Path(db_path).exists():
            print("✓ Local database file exists")
            
            # Test lookup
            url = "http://test-phishing.com"
            result = phishtank_lookup(url)
            
            if result['source'] == 'local_db':
                print(f"\n✓ Local database lookup successful")
                print(f"  URL: {result['url']}")
                print(f"  In Database: {result['in_database']}")
            else:
                print(f"\n  Lookup source: {result['source']}")
        else:
            print("✗ Local database file not found")
            print(f"  Run: python tools/phishtank_update.py")
    else:
        print("\nTo enable local database:")
        print("  1. Set PHISHTANK_USE_LOCAL_DUMP=true in .env")
        print("  2. Run: python tools/phishtank_update.py")


def main():
    """Run all demos."""
    print("\n" + "=" * 60)
    print("PhishTank Integration Demo")
    print("=" * 60)
    
    try:
        demo_api_lookup()
        demo_caching()
        demo_skip_signature()
        demo_local_db()
        
        print("\n" + "=" * 60)
        print("Demo Complete!")
        print("=" * 60)
        
        # Final metrics
        print("\nFinal Metrics:")
        metrics = get_metrics()
        for key, value in metrics.items():
            print(f"  {key}: {value}")
        
    except Exception as e:
        print(f"\n✗ Error during demo: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
