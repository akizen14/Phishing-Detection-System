"""
NCD Threshold Tuning Script

Computes similarity distributions between prototype sets to determine
optimal NCD threshold for phishing detection.

Usage:
    python tools/tune_threshold.py
"""
import sys
from pathlib import Path

# Add parent directory to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.ncd import ncd
from src.prototypes import PHISH_PROTOTYPES, LEGIT_PROTOTYPES


def compute_pairs(a, b):
    """
    Compute NCD scores for all pairs between two sets.
    
    Args:
        a: First set of prototypes
        b: Second set of prototypes
        
    Returns:
        List of NCD scores
    """
    scores = []
    for x in a:
        for y in b:
            scores.append(ncd(x, y))
    return scores


def main():
    print("=" * 60)
    print("NCD Threshold Tuning Analysis")
    print("=" * 60)
    print()
    
    # Check if prototypes are loaded
    if not LEGIT_PROTOTYPES:
        print("ERROR: No legit prototypes loaded!")
        print("Please ensure samples/legit/*.dom files exist.")
        return
    
    if not PHISH_PROTOTYPES:
        print("ERROR: No phishing prototypes loaded!")
        print("Please ensure samples/phishing/*.dom files exist.")
        return
    
    print(f"Loaded prototypes:")
    print(f"  - Legit: {len(LEGIT_PROTOTYPES)} samples")
    print(f"  - Phishing: {len(PHISH_PROTOTYPES)} samples")
    print()
    print("Computing NCD similarity distributions...")
    print("(This may take a few minutes depending on prototype count)")
    print()

    # Compute L→L (Legit to Legit)
    ll = compute_pairs(LEGIT_PROTOTYPES, LEGIT_PROTOTYPES)
    ll = [x for x in ll if x != 0]  # filter out self-comparisons

    # Compute L→P (Legit to Phish)
    lp = compute_pairs(LEGIT_PROTOTYPES, PHISH_PROTOTYPES)

    # Display results
    print("-" * 60)
    print("Legit-to-Legit (L->L) scores:")
    print(f"  Comparisons: {len(ll)}")
    print(f"  Scores: {[round(x, 4) for x in ll]}")
    print(f"  Min: {min(ll):.4f}")
    print(f"  Max: {max(ll):.4f}")
    print(f"  Avg: {sum(ll)/len(ll):.4f}")
    print()

    print("-" * 60)
    print("Legit-to-Phish (L->P) scores:")
    print(f"  Comparisons: {len(lp)}")
    print(f"  Scores: {[round(x, 4) for x in lp[:10]]}... (showing first 10)")
    print(f"  Min: {min(lp):.4f}")
    print(f"  Max: {max(lp):.4f}")
    print(f"  Avg: {sum(lp)/len(lp):.4f}")
    print()

    # Recommendations
    print("=" * 60)
    print("THRESHOLD RECOMMENDATION")
    print("=" * 60)
    print()
    print("Ideal threshold should be:")
    print(f"  Lower bound = max(L->L) = {max(ll):.4f}")
    print(f"    (Above this, legit sites won't match each other)")
    print()
    print(f"  Upper bound = min(L->P) = {min(lp):.4f}")
    print(f"    (Below this, legit sites won't match phishing sites)")
    print()
    
    # Calculate suggested threshold
    suggested = (max(ll) + min(lp)) / 2
    print(f"  Suggested threshold: {suggested:.4f}")
    print(f"    (Midpoint between bounds)")
    print()
    
    # Check current threshold
    from src.detector import NCD_THRESHOLD
    print(f"  Current threshold in detector.py: {NCD_THRESHOLD}")
    print()
    
    if max(ll) < min(lp):
        print("GOOD: Clear separation between L->L and L->P distributions")
        print(f"  Any threshold in range [{max(ll):.4f}, {min(lp):.4f}] should work well.")
    else:
        print("WARNING: L->L and L->P distributions overlap!")
        print("  Consider collecting more diverse prototypes.")
    
    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
