"""
Feature Extraction Layer for Phishing Detection System.

Converts sanitized DOM into machine-learning-ready numerical features.
"""
import math
import logging
from typing import Dict, List
from collections import Counter

from bs4 import BeautifulSoup
from src.ncd import ncd
from src.prototypes_clustered import (
    PHISH_CLUSTER_1, PHISH_CLUSTER_2, PHISH_CLUSTER_3, LEGIT_PROTOTYPES
)

logger = logging.getLogger("features")


def extract_tag_features(dom_html: str) -> Dict[str, float]:
    """
    Extract tag-based features from DOM.
    
    Args:
        dom_html: Sanitized HTML string
        
    Returns:
        Dictionary of tag-based features
    """
    try:
        soup = BeautifulSoup(dom_html, "html.parser")
        
        # Get all tags
        all_tags = [tag.name for tag in soup.find_all()]
        total_tag_count = len(all_tags)
        
        if total_tag_count == 0:
            return {
                "total_tag_count": 0.0,
                "unique_tag_count": 0.0,
                "depth_of_dom_tree": 0.0,
                "average_children_per_node": 0.0,
                "count_form": 0.0,
                "count_input": 0.0,
                "count_script": 0.0,
                "count_img": 0.0,
                "count_iframe": 0.0,
                "count_link": 0.0,
                "count_meta": 0.0
            }
        
        # Unique tag count
        unique_tag_count = len(set(all_tags))
        
        # Count specific tags
        tag_counter = Counter(all_tags)
        count_form = float(tag_counter.get("form", 0))
        count_input = float(tag_counter.get("input", 0))
        count_script = float(tag_counter.get("script", 0))
        count_img = float(tag_counter.get("img", 0))
        count_iframe = float(tag_counter.get("iframe", 0))
        count_link = float(tag_counter.get("link", 0))
        count_meta = float(tag_counter.get("meta", 0))
        
        # Calculate DOM tree depth
        def get_depth(node, current_depth=0):
            """Recursively calculate maximum depth of DOM tree."""
            if not node.children:
                return current_depth
            max_child_depth = current_depth
            for child in node.children:
                if hasattr(child, 'name') and child.name:  # Only count actual tags
                    child_depth = get_depth(child, current_depth + 1)
                    max_child_depth = max(max_child_depth, child_depth)
            return max_child_depth
        
        depth_of_dom_tree = float(get_depth(soup))
        
        # Calculate average children per node
        def count_children(node):
            """Count all child nodes recursively."""
            count = 0
            for child in node.children:
                if hasattr(child, 'name') and child.name:
                    count += 1
                    count += count_children(child)
            return count
        
        total_children = count_children(soup)
        # Subtract 1 because root doesn't count as its own child
        num_nodes = total_tag_count
        average_children_per_node = float(total_children / num_nodes) if num_nodes > 0 else 0.0
        
        return {
            "total_tag_count": float(total_tag_count),
            "unique_tag_count": float(unique_tag_count),
            "depth_of_dom_tree": depth_of_dom_tree,
            "average_children_per_node": average_children_per_node,
            "count_form": count_form,
            "count_input": count_input,
            "count_script": count_script,
            "count_img": count_img,
            "count_iframe": count_iframe,
            "count_link": count_link,
            "count_meta": count_meta
        }
    except Exception as e:
        logger.error(f"Error extracting tag features: {e}")
        return {
            "total_tag_count": 0.0,
            "unique_tag_count": 0.0,
            "depth_of_dom_tree": 0.0,
            "average_children_per_node": 0.0,
            "count_form": 0.0,
            "count_input": 0.0,
            "count_script": 0.0,
            "count_img": 0.0,
            "count_iframe": 0.0,
            "count_link": 0.0,
            "count_meta": 0.0
        }


def calculate_shannon_entropy(sequence: str) -> float:
    """
    Calculate Shannon entropy of a sequence.
    
    Args:
        sequence: Input sequence (e.g., tag sequence)
        
    Returns:
        Shannon entropy value
    """
    if not sequence:
        return 0.0
    
    # Count character frequencies
    char_counts = Counter(sequence)
    length = len(sequence)
    
    # Calculate entropy
    entropy = 0.0
    for count in char_counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def extract_structure_features(dom_html: str, dom_bytes: bytes) -> Dict[str, float]:
    """
    Extract structure-based features from DOM.
    
    Args:
        dom_html: Sanitized HTML string
        dom_bytes: DOM as bytes
        
    Returns:
        Dictionary of structure-based features
    """
    try:
        soup = BeautifulSoup(dom_html, "html.parser")
        
        # Get tag sequence for entropy calculation
        tag_sequence = " ".join([tag.name for tag in soup.find_all()])
        dom_entropy = calculate_shannon_entropy(tag_sequence)
        
        # Token count (split by whitespace)
        dom_token_count = float(len(tag_sequence.split()))
        
        # DOM length in bytes
        dom_length_bytes = float(len(dom_bytes))
        
        # Ratio of interactive tags
        all_tags = [tag.name for tag in soup.find_all()]
        total_tags = len(all_tags)
        
        if total_tags == 0:
            ratio_interactive_tags = 0.0
        else:
            tag_counter = Counter(all_tags)
            interactive_count = (
                tag_counter.get("form", 0) +
                tag_counter.get("input", 0) +
                tag_counter.get("button", 0)
            )
            ratio_interactive_tags = float(interactive_count / total_tags)
        
        return {
            "dom_entropy": dom_entropy,
            "dom_token_count": dom_token_count,
            "dom_length_bytes": dom_length_bytes,
            "ratio_interactive_tags": ratio_interactive_tags
        }
    except Exception as e:
        logger.error(f"Error extracting structure features: {e}")
        return {
            "dom_entropy": 0.0,
            "dom_token_count": 0.0,
            "dom_length_bytes": float(len(dom_bytes)),
            "ratio_interactive_tags": 0.0
        }


def compute_ncd_to_prototypes(dom_bytes: bytes) -> Dict[str, float]:
    """
    Compute NCD distances to prototype sets.
    
    Args:
        dom_bytes: Sanitized DOM as bytes
        
    Returns:
        Dictionary of NCD distances to different prototype sets
    """
    features = {}
    
    try:
        # Compute NCD to phishing clusters
        if PHISH_CLUSTER_1:
            scores_c1 = [ncd(dom_bytes, p) for p in PHISH_CLUSTER_1]
            features["ncd_phish_cluster_1_min"] = float(min(scores_c1))
            features["ncd_phish_cluster_1_avg"] = float(sum(scores_c1) / len(scores_c1))
        else:
            features["ncd_phish_cluster_1_min"] = 1.0
            features["ncd_phish_cluster_1_avg"] = 1.0
        
        if PHISH_CLUSTER_2:
            scores_c2 = [ncd(dom_bytes, p) for p in PHISH_CLUSTER_2]
            features["ncd_phish_cluster_2_min"] = float(min(scores_c2))
            features["ncd_phish_cluster_2_avg"] = float(sum(scores_c2) / len(scores_c2))
        else:
            features["ncd_phish_cluster_2_min"] = 1.0
            features["ncd_phish_cluster_2_avg"] = 1.0
        
        if PHISH_CLUSTER_3:
            scores_c3 = [ncd(dom_bytes, p) for p in PHISH_CLUSTER_3]
            features["ncd_phish_cluster_3_min"] = float(min(scores_c3))
            features["ncd_phish_cluster_3_avg"] = float(sum(scores_c3) / len(scores_c3))
        else:
            features["ncd_phish_cluster_3_min"] = 1.0
            features["ncd_phish_cluster_3_avg"] = 1.0
        
        # Compute NCD to legitimate prototypes
        if LEGIT_PROTOTYPES:
            legit_scores = [ncd(dom_bytes, p) for p in LEGIT_PROTOTYPES]
            features["ncd_legit_min"] = float(min(legit_scores))
            features["ncd_legit_avg"] = float(sum(legit_scores) / len(legit_scores))
        else:
            features["ncd_legit_min"] = 1.0
            features["ncd_legit_avg"] = 1.0
        
        # Compute best overall scores
        phish_mins = [
            features["ncd_phish_cluster_1_min"],
            features["ncd_phish_cluster_2_min"],
            features["ncd_phish_cluster_3_min"]
        ]
        features["ncd_phish_best"] = float(min(phish_mins))
        
        # Average of all phishing cluster averages
        phish_avgs = [
            features["ncd_phish_cluster_1_avg"],
            features["ncd_phish_cluster_2_avg"],
            features["ncd_phish_cluster_3_avg"]
        ]
        features["ncd_phish_avg"] = float(sum(phish_avgs) / len(phish_avgs))
        
    except Exception as e:
        logger.error(f"Error computing NCD to prototypes: {e}")
        # Return default values on error
        features = {
            "ncd_phish_cluster_1_min": 1.0,
            "ncd_phish_cluster_1_avg": 1.0,
            "ncd_phish_cluster_2_min": 1.0,
            "ncd_phish_cluster_2_avg": 1.0,
            "ncd_phish_cluster_3_min": 1.0,
            "ncd_phish_cluster_3_avg": 1.0,
            "ncd_legit_min": 1.0,
            "ncd_legit_avg": 1.0,
            "ncd_phish_best": 1.0,
            "ncd_phish_avg": 1.0
        }
    
    return features


def extract_features(dom: str) -> Dict[str, float]:
    """
    Extract all features from a sanitized DOM string.
    
    This is the main feature extraction function that combines:
    - Tag-based features
    - Structure-based features
    - Similarity-based features (NCD)
    
    Args:
        dom: Sanitized DOM string (HTML)
        
    Returns:
        Dictionary of all extracted features with stable names
    """
    if not dom:
        logger.warning("Empty DOM provided for feature extraction")
        return _get_empty_features()
    
    try:
        # Convert to bytes for NCD computation
        dom_bytes = dom.encode("utf-8") if isinstance(dom, str) else dom
        
        # Extract all feature categories
        tag_features = extract_tag_features(dom)
        structure_features = extract_structure_features(dom, dom_bytes)
        ncd_features = compute_ncd_to_prototypes(dom_bytes)
        
        # Combine all features
        all_features = {
            **tag_features,
            **structure_features,
            **ncd_features
        }
        
        logger.debug(f"Extracted {len(all_features)} features from DOM")
        return all_features
        
    except Exception as e:
        logger.error(f"Error in extract_features: {e}")
        return _get_empty_features()


def _get_empty_features() -> Dict[str, float]:
    """
    Return a dictionary with all feature names set to 0.0.
    
    Returns:
        Dictionary with all feature names initialized to 0.0
    """
    return {
        # Tag-based features
        "total_tag_count": 0.0,
        "unique_tag_count": 0.0,
        "depth_of_dom_tree": 0.0,
        "average_children_per_node": 0.0,
        "count_form": 0.0,
        "count_input": 0.0,
        "count_script": 0.0,
        "count_img": 0.0,
        "count_iframe": 0.0,
        "count_link": 0.0,
        "count_meta": 0.0,
        # Structure-based features
        "dom_entropy": 0.0,
        "dom_token_count": 0.0,
        "dom_length_bytes": 0.0,
        "ratio_interactive_tags": 0.0,
        # NCD similarity features
        "ncd_phish_cluster_1_min": 1.0,
        "ncd_phish_cluster_1_avg": 1.0,
        "ncd_phish_cluster_2_min": 1.0,
        "ncd_phish_cluster_2_avg": 1.0,
        "ncd_phish_cluster_3_min": 1.0,
        "ncd_phish_cluster_3_avg": 1.0,
        "ncd_legit_min": 1.0,
        "ncd_legit_avg": 1.0,
        "ncd_phish_best": 1.0,
        "ncd_phish_avg": 1.0
    }


