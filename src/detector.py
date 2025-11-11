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
from src.render import render_page_source
from src.resource_graph import extract_resource_signature

logger = logging.getLogger("detector")

# NCD threshold for classification
# Updated to 0.48 based on expanded prototype dataset (17 legit + 17 phishing)
# This provides better balance between false positives and false negatives
NCD_THRESHOLD = 0.48

# Small DOM threshold - switch to resource signature mode
SMALL_DOM_THRESHOLD = 2000  # bytes


def classify_url_ncd(url: str) -> Dict:
    """
    Classify a URL using NCD with automatic fallback to resource signature
    for small DOM pages.
    
    Detection strategy:
    1. Extract sanitized DOM
    2. If DOM < 2000 bytes → Use resource signature (for dynamic content)
    3. Otherwise → Use DOM structure
    
    Args:
        url: URL to classify
        
    Returns:
        Dictionary with verdict, NCD scores, cluster info, and source
    """
    # Extract sanitized DOM
    dom_bytes = extract_sanitized_dom(url)
    if not dom_bytes:
        logger.error(f"Failed to extract DOM for {url}")
        return {
            "verdict": "unknown",
            "ncd_score_phish_best": 1.0,
            "ncd_score_legit_best": 1.0,
            "source": "error",
            "error": "Unable to extract DOM from URL"
        }
    
    dom_length = len(dom_bytes)
    logger.info(f"DOM length: {dom_length} bytes")
    
    # Check if DOM is too small (likely dynamic content)
    if dom_length < SMALL_DOM_THRESHOLD:
        logger.info(f"Small DOM detected ({dom_length} < {SMALL_DOM_THRESHOLD}), switching to resource signature mode")
        
        # Render page to get full HTML with resources
        html = render_page_source(url, wait_seconds=3, headless=True)
        if not html:
            logger.error(f"Failed to render page for resource extraction: {url}")
            return {
                "verdict": "unknown",
                "ncd_score_phish_best": 1.0,
                "ncd_score_legit_best": 1.0,
                "source": "error",
                "error": "Unable to render page for resource extraction"
            }
        
        # Extract resource signature
        resource_sig = extract_resource_signature(html, base_url=url)
        logger.info(f"Resource signature length: {len(resource_sig)} bytes")
        
        # Classify using resource signature
        result = classify_dom_ncd(resource_sig)
        result["detection_mode"] = "resource-signature"
        result["dom_length"] = dom_length
        result["resource_sig_length"] = len(resource_sig)
        return result
    else:
        # Normal DOM-based classification
        logger.info(f"Normal DOM size, using DOM structure classification")
        result = classify_dom_ncd(dom_bytes)
        result["detection_mode"] = "dom-structure"
        result["dom_length"] = dom_length
        return result


def classify_dom_ncd(dom_bytes: bytes) -> Dict:
    """
    Classify a DOM using NCD comparison against clustered prototype sets.
    
    Uses structural clustering to identify phishing category and compare
    against legitimate prototypes.
    
    Args:
        dom_bytes: Sanitized DOM as bytes
        
    Returns:
        Dictionary with verdict, NCD scores, cluster info, and source
    """
    from src.prototypes_clustered import (
        PHISH_CLUSTER_1, PHISH_CLUSTER_2, PHISH_CLUSTER_3, LEGIT_PROTOTYPES
    )
    
    # Check if prototypes are loaded
    total_phish = len(PHISH_CLUSTER_1) + len(PHISH_CLUSTER_2) + len(PHISH_CLUSTER_3)
    if total_phish == 0 and len(LEGIT_PROTOTYPES) == 0:
        logger.warning("No prototypes loaded. Cannot perform NCD classification.")
        return {
            "verdict": "unknown",
            "ncd_score_phish_best": 1.0,
            "ncd_score_legit_best": 1.0,
            "source": "ncd",
            "error": "No prototypes available"
        }
    
    # Compute NCD against each cluster
    cluster_scores = {}
    
    if PHISH_CLUSTER_1:
        scores_c1 = [ncd(dom_bytes, p) for p in PHISH_CLUSTER_1]
        cluster_scores['cluster_1'] = min(scores_c1)
    else:
        cluster_scores['cluster_1'] = 1.0
    
    if PHISH_CLUSTER_2:
        scores_c2 = [ncd(dom_bytes, p) for p in PHISH_CLUSTER_2]
        cluster_scores['cluster_2'] = min(scores_c2)
    else:
        cluster_scores['cluster_2'] = 1.0
    
    if PHISH_CLUSTER_3:
        scores_c3 = [ncd(dom_bytes, p) for p in PHISH_CLUSTER_3]
        cluster_scores['cluster_3'] = min(scores_c3)
    else:
        cluster_scores['cluster_3'] = 1.0
    
    # Compute NCD against legitimate prototypes
    if LEGIT_PROTOTYPES:
        legit_scores = [ncd(dom_bytes, p) for p in LEGIT_PROTOTYPES]
        best_legit = min(legit_scores)
    else:
        best_legit = 1.0
    
    # Find best phishing cluster
    best_cluster = min(cluster_scores, key=cluster_scores.get)
    best_phish = cluster_scores[best_cluster]
    
    # Classification logic with explanation
    if best_phish < best_legit and best_phish < NCD_THRESHOLD:
        # Classify as phishing with cluster info
        if best_cluster == 'cluster_1':
            verdict = "phish-cluster-1"
        elif best_cluster == 'cluster_2':
            verdict = "phish-cluster-2"
        else:
            verdict = "phish-cluster-3"
        
        # Generate explanation for phishing verdict
        reason = (f"Classified as phishing because closest structural match was {best_cluster} "
                  f"(NCD score: {best_phish:.3f}) which is below the threshold ({NCD_THRESHOLD}) "
                  f"and more similar than legitimate prototypes (NCD score: {best_legit:.3f}). "
                  f"Lower NCD scores indicate higher structural similarity.")
    else:
        verdict = "legit"
        
        # Generate explanation for legitimate verdict
        if best_legit < best_phish:
            reason = (f"Classified as legitimate because closest match was legitimate prototypes "
                      f"(NCD score: {best_legit:.3f}) which is more similar than any phishing cluster "
                      f"(best phishing: {best_cluster} with score {best_phish:.3f}).")
        else:
            reason = (f"Classified as legitimate because best phishing match ({best_cluster} with "
                      f"score {best_phish:.3f}) is above the threshold ({NCD_THRESHOLD}), indicating "
                      f"insufficient similarity to known phishing patterns.")
    
    logger.info(f"NCD classification: verdict={verdict}, best_cluster={best_cluster}, "
                f"phish={best_phish:.4f}, legit={best_legit:.4f}")
    
    return {
        "verdict": verdict,
        "ncd_score_phish_best": round(best_phish, 4),
        "ncd_score_legit_best": round(best_legit, 4),
        "ncd_cluster_1": round(cluster_scores['cluster_1'], 4),
        "ncd_cluster_2": round(cluster_scores['cluster_2'], 4),
        "ncd_cluster_3": round(cluster_scores['cluster_3'], 4),
        "best_cluster": best_cluster,
        "source": "ncd-clustered",
        "reason": reason
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
