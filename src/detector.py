"""
Core detection logic for phishing URL classification using NCD.
"""
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

from src.extract_dom import extract_sanitized_dom
from src.ncd import ncd
from src.config import SAMPLES_DIR, DEFAULT_NCD_THRESHOLD

logger = logging.getLogger("detector")

# NCD threshold for classification
NCD_THRESHOLD = 0.38


def classify_dom_ncd(dom_bytes: bytes) -> Dict:
    """
    Classify a DOM using NCD comparison against prototype sets.
    
    Args:
        dom_bytes: Sanitized DOM as bytes
        
    Returns:
        Dictionary with verdict, NCD scores, and source
    """
    from src.prototypes import PHISH_PROTOTYPES, LEGIT_PROTOTYPES
    
    if not PHISH_PROTOTYPES and not LEGIT_PROTOTYPES:
        logger.warning("No prototypes loaded. Cannot perform NCD classification.")
        return {
            "verdict": "unknown",
            "ncd_score_phish_best": 1.0,
            "ncd_score_legit_best": 1.0,
            "source": "ncd",
            "error": "No prototypes available"
        }
    
    # Compute NCD against all prototypes
    phish_scores = [ncd(dom_bytes, p) for p in PHISH_PROTOTYPES] if PHISH_PROTOTYPES else [1.0]
    legit_scores = [ncd(dom_bytes, p) for p in LEGIT_PROTOTYPES] if LEGIT_PROTOTYPES else [1.0]
    
    best_phish = min(phish_scores)
    best_legit = min(legit_scores)
    
    # Classification logic
    if best_phish < best_legit and best_phish < NCD_THRESHOLD:
        verdict = "phish"
    else:
        verdict = "legit"
    
    logger.info(f"NCD classification: verdict={verdict}, phish={best_phish:.4f}, legit={best_legit:.4f}")
    
    return {
        "verdict": verdict,
        "ncd_score_phish_best": round(best_phish, 4),
        "ncd_score_legit_best": round(best_legit, 4),
        "source": "ncd"
    }


def classify_url(url: str, dataset: List[Dict], threshold: float = DEFAULT_NCD_THRESHOLD) -> Dict:
    """
    Compare a new URL's DOM with samples to detect phishing.
    
    Args:
        url: URL to classify
        dataset: List of sample dictionaries with 'dom', 'meta', and 'label' keys
        threshold: NCD threshold for classification
        
    Returns:
        Dictionary with classification results
    """
    dom = extract_sanitized_dom(url)
    if not dom:
        return {"url": url, "error": "Unable to fetch DOM", "classification": "error"}

    min_distance = 1.0
    label = "unknown"
    closest_sample = None
    
    # Use NCD for comparison
    for sample in dataset:
        dist = ncd(dom, sample["dom"])
        if dist < min_distance:
            min_distance = dist
            label = sample["label"]
            closest_sample = sample["meta"].get("url", "unknown")

    # If distance is too high, classify as potential phishing
    if min_distance > threshold:
        label = "phish"

    return {
        "url": url, 
        "ncd": round(min_distance, 4), 
        "classification": label,
        "closest_sample": closest_sample
    }


def load_dataset(samples_dir: Optional[Path] = None) -> List[Dict]:
    """
    Load all DOM samples from the samples directory.
    
    Args:
        samples_dir: Path to samples directory (defaults to config.SAMPLES_DIR)
        
    Returns:
        List of sample dictionaries with 'dom', 'meta', and 'label' keys
    """
    if samples_dir is None:
        samples_dir = SAMPLES_DIR
    
    if not samples_dir.exists():
        print(f"[WARNING] Samples directory not found: {samples_dir}")
        return []
    
    dataset = []
    
    for dom_file in sorted(samples_dir.glob("*.dom")):
        meta_file = dom_file.with_suffix(".meta.json")
        
        if not meta_file.exists():
            print(f"[WARNING] Missing metadata for {dom_file.name}")
            continue
        
        try:
            with open(dom_file, "rb") as f_dom:
                dom_bytes = f_dom.read()
            
            with open(meta_file, "r", encoding="utf-8") as f_meta:
                meta = json.load(f_meta)
            
            label = meta.get("label", "legit")
            
            dataset.append({
                "dom": dom_bytes,
                "meta": meta,
                "label": label
            })
        except Exception as e:
            print(f"[ERROR] Loading sample {dom_file.name}: {e}")
    
    print(f"Loaded {len(dataset)} samples from {samples_dir}")
    return dataset
