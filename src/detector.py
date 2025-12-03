"""
Core detection logic for phishing URL classification using NCD.
"""
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

from src.extract_dom import extract_sanitized_dom
from src.ncd import ncd
from src.config import (
    SAMPLES_DIR, DEFAULT_NCD_THRESHOLD, DEFAULT_WAIT_SECONDS,
    NCD_MIN_SEPARATION_MARGIN, NCD_CLOSE_MARGIN,
    NCD_ABSOLUTE_THRESHOLD, NCD_CONSERVATIVE_BIAS,
    ML_ENABLED, MODEL_PATH, ML_CONFIDENCE_THRESHOLD,
    MINIMAL_DOM_THRESHOLD, MINIMAL_DOM_PENALTY
)
from src.render import render_page_source
from src.resource_graph import extract_resource_signature
from src.features import extract_features

logger = logging.getLogger("detector")

# ML Model (loaded lazily)
_ml_model = None

def _load_ml_model():
    """Load ML model if enabled and available."""
    global _ml_model
    if _ml_model is None and ML_ENABLED:
        try:
            from src.model import PhishingDetectorModel
            _ml_model = PhishingDetectorModel.load(MODEL_PATH)
            logger.info(f"ML model loaded from {MODEL_PATH}")
        except Exception as e:
            logger.warning(f"Failed to load ML model: {e}. Falling back to NCD-only mode.")
            _ml_model = False  # Mark as failed to avoid retrying
    return _ml_model

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
    try:
        dom_bytes = extract_sanitized_dom(url)
        if not dom_bytes:
            logger.error(f"Failed to extract DOM for {url} - render returned None")
            # Try to get features even if DOM extraction failed
            html_for_features = render_page_source(url, wait_seconds=DEFAULT_WAIT_SECONDS, headless=True)
            features = extract_features(html_for_features) if html_for_features else {}
            return {
                "verdict": "unknown",
                "ncd_score_phish_best": 1.0,
                "ncd_score_legit_best": 1.0,
                "source": "error",
                "error": "Unable to extract DOM from URL. Please check if ChromeDriver is configured correctly and the URL is accessible.",
                "features": features
            }
    except Exception as e:
        logger.error(f"Exception during DOM extraction for {url}: {e}")
        # Try to get features even on error
        try:
            html_for_features = render_page_source(url, wait_seconds=DEFAULT_WAIT_SECONDS, headless=True)
            features = extract_features(html_for_features) if html_for_features else {}
        except:
            features = {}
        return {
            "verdict": "unknown",
            "ncd_score_phish_best": 1.0,
            "ncd_score_legit_best": 1.0,
            "source": "error",
            "error": f"Error extracting DOM: {str(e)}",
            "features": features
        }
    
    dom_length = len(dom_bytes)
    logger.info(f"DOM length: {dom_length} bytes")
    
    # Get full HTML for feature extraction (features need full structure)
    html_for_features = render_page_source(url, wait_seconds=DEFAULT_WAIT_SECONDS, headless=True)
    
    # Extract features from full HTML
    features = {}
    if html_for_features:
        try:
            features = extract_features(html_for_features)
            logger.info(f"Extracted {len(features)} features from DOM")
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            features = {}
    else:
        logger.warning("Could not get HTML for feature extraction, using empty features")
    
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
                "error": "Unable to render page for resource extraction",
                "features": features
            }
        
        # Extract resource signature
        resource_sig = extract_resource_signature(html, base_url=url)
        logger.info(f"Resource signature length: {len(resource_sig)} bytes")
        
        # Classify using resource signature
        result = classify_dom_ncd(resource_sig)
        result["detection_mode"] = "resource-signature"
        result["dom_length"] = dom_length
        result["resource_sig_length"] = len(resource_sig)
        result["features"] = features
        
        # Add ML prediction if enabled
        ml_model = _load_ml_model()
        if ml_model and features:
            try:
                ml_prediction = ml_model.predict(features)
                result["ml_prediction"] = ml_prediction
                
                # Hybrid decision logic
                ml_confidence = ml_prediction.get("probability", 0.0)
                ml_label = ml_prediction.get("label", "legit")
                
                if ml_confidence >= ML_CONFIDENCE_THRESHOLD:
                    logger.info(f"ML prediction: {ml_label} (confidence: {ml_confidence:.4f}) - Using ML result")
                    result["final_verdict"] = ml_label
                    result["decision_source"] = "ml"
                else:
                    logger.info(f"ML prediction: {ml_label} (confidence: {ml_confidence:.4f}) - Using NCD result")
                    result["final_verdict"] = result["verdict"]
                    result["decision_source"] = "ncd"
            except Exception as e:
                logger.error(f"ML prediction failed: {e}. Using NCD result only.")
                result["decision_source"] = "ncd"
        else:
            result["decision_source"] = "ncd"
        
        return result
    else:
        # Normal DOM-based classification
        logger.info(f"Normal DOM size, using DOM structure classification")
        result = classify_dom_ncd(dom_bytes)
        result["detection_mode"] = "dom-structure"
        result["dom_length"] = dom_length
        result["features"] = features
        
        # Add ML prediction if enabled
        ml_model = _load_ml_model()
        if ml_model and features:
            try:
                ml_prediction = ml_model.predict(features)
                result["ml_prediction"] = ml_prediction
                
                # Hybrid decision logic
                ml_confidence = ml_prediction.get("probability", 0.0)
                ml_label = ml_prediction.get("label", "legit")
                
                # If ML confidence is high, use ML result
                # Otherwise, use NCD result
                if ml_confidence >= ML_CONFIDENCE_THRESHOLD:
                    logger.info(f"ML prediction: {ml_label} (confidence: {ml_confidence:.4f}) - Using ML result")
                    result["final_verdict"] = ml_label
                    result["decision_source"] = "ml"
                else:
                    logger.info(f"ML prediction: {ml_label} (confidence: {ml_confidence:.4f}) - Using NCD result (low confidence)")
                    result["final_verdict"] = result["verdict"]
                    result["decision_source"] = "ncd"
            except Exception as e:
                logger.error(f"ML prediction failed: {e}. Using NCD result only.")
                result["decision_source"] = "ncd"
        else:
            result["decision_source"] = "ncd"
        
        return result


def classify_dom_ncd(dom_bytes: bytes) -> Dict:
    """
    Prototype-based NCD classification using FPF-selected prototypes.
    
    Compares test DOM against prototypes and classifies based on:
    - Minimum distance to prototypes (best match)
    - Average distance to prototypes
    
    Classification: 'phish' if phish_min < legit_min, else 'legit'
    
    Args:
        dom_bytes: Sanitized DOM as bytes
        
    Returns:
        Dictionary with verdict, prototype scores, and source
    """
    from src.prototypes import load_prototypes
    
    # Load prototypes
    phish_prototypes, legit_prototypes = load_prototypes()
    
    # Check if prototypes are available
    if not phish_prototypes and not legit_prototypes:
        logger.warning("No prototypes loaded. Cannot perform NCD classification.")
        return {
            "verdict": "unknown",
            "prototype_scores": {
                "phish_min": 1.0,
                "phish_avg": 1.0,
                "legit_min": 1.0,
                "legit_avg": 1.0
            },
            "source": "prototype",
            "error": "No prototypes available. Run tools/build_prototypes.py first."
        }
    
    # Compute distances to phishing prototypes
    if phish_prototypes:
        phish_scores = [ncd(dom_bytes, p) for p in phish_prototypes]
        phish_min = min(phish_scores)
        phish_avg = sum(phish_scores) / len(phish_scores)
    else:
        phish_scores = []
        phish_min = 1.0
        phish_avg = 1.0
        logger.warning("No phishing prototypes available")
    
    # Compute distances to legitimate prototypes
    if legit_prototypes:
        legit_scores = [ncd(dom_bytes, p) for p in legit_prototypes]
        legit_min = min(legit_scores)
        legit_avg = sum(legit_scores) / len(legit_scores)
    else:
        legit_scores = []
        legit_min = 1.0
        legit_avg = 1.0
        logger.warning("No legitimate prototypes available")
    
    # Get DOM size for minimal DOM penalty
    dom_size = len(dom_bytes)
    minimal_dom_adjustment_applied = False
    
    # Apply minimal DOM penalty: minimal pages statistically correlate with phishing
    # (redirect pages, obfuscated JS loaders, etc.)
    if dom_size < MINIMAL_DOM_THRESHOLD:
        # Add penalty to legitimate scores to favor phishing classification
        legit_min_adj = legit_min + MINIMAL_DOM_PENALTY
        legit_avg_adj = legit_avg + MINIMAL_DOM_PENALTY
        minimal_dom_adjustment_applied = True
        logger.info(f"Minimal DOM detected ({dom_size} bytes < {MINIMAL_DOM_THRESHOLD}). Applying penalty: +{MINIMAL_DOM_PENALTY} to legitimate scores")
    else:
        legit_min_adj = legit_min
        legit_avg_adj = legit_avg
    
    # Use adjusted scores for classification
    phish_min_adj = phish_min
    phish_avg_adj = phish_avg
    
    # Classification logic: phish if phish_min_adj < legit_min_adj, else legit
    if phish_min_adj < legit_min_adj:
        verdict = "phish"
        if minimal_dom_adjustment_applied:
            final_decision = f"Phishing prototype match ({phish_min:.4f}) better than adjusted legitimate ({legit_min_adj:.4f}, original: {legit_min:.4f})"
        else:
            final_decision = f"Phishing prototype match ({phish_min:.4f}) better than legitimate ({legit_min:.4f})"
    else:
        verdict = "legit"
        if minimal_dom_adjustment_applied:
            final_decision = f"Legitimate prototype match ({legit_min_adj:.4f}, original: {legit_min:.4f}) better than phishing ({phish_min:.4f})"
        else:
            final_decision = f"Legitimate prototype match ({legit_min:.4f}) better than phishing ({phish_min:.4f})"
    
    # Determine confidence based on separation (using adjusted scores)
    difference = abs(phish_min_adj - legit_min_adj)
    if difference > 0.1:
        confidence = "high"
    elif difference > 0.05:
        confidence = "medium"
    else:
        confidence = "low"
    
    logger.info(f"Prototype classification: {verdict} (phish_min={phish_min:.4f}, legit_min={legit_min:.4f}, legit_min_adj={legit_min_adj:.4f}, diff={difference:.4f}, minimal_adj={minimal_dom_adjustment_applied})")
    
    # Build reason string
    reason = (f"Classified as {verdict}. "
             f"Phishing prototype distances: min={phish_min:.4f}, avg={phish_avg:.4f}. "
             f"Legitimate prototype distances: min={legit_min:.4f}, avg={legit_avg:.4f}. ")
    if minimal_dom_adjustment_applied:
        reason += f"Minimal DOM penalty applied (+{MINIMAL_DOM_PENALTY}). "
    reason += f"{final_decision}"
    
    return {
        "verdict": verdict,
        "prototype_scores": {
            "phish_min": round(phish_min, 4),
            "phish_avg": round(phish_avg, 4),
            "legit_min": round(legit_min, 4),
            "legit_avg": round(legit_avg, 4)
        },
        "dom_size": dom_size,
        "minimal_dom_adjustment_applied": minimal_dom_adjustment_applied,
        "final_decision": final_decision,
        "source": "prototype",
        "reason": reason,
        "confidence": confidence,
        # Backward compatibility: keep old field names
        "ncd_score_phish_best": round(phish_min, 4),
        "ncd_score_legit_best": round(legit_min, 4),
        "ncd_score_phish_avg": round(phish_avg, 4),
        "ncd_score_legit_avg": round(legit_avg, 4)
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
