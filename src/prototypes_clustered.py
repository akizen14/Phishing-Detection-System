"""
Clustered DOM prototype loader for NCD-based phishing detection.

Loads pre-clustered phishing prototypes organized by structural similarity,
plus legitimate prototypes for comparison.
"""
import os
import logging
from pathlib import Path
from typing import List

from src.config import ROOT_DIR

logger = logging.getLogger("prototypes_clustered")

# Prototype directories
PHISHING_CLUSTERED_DIR = ROOT_DIR / "samples" / "phishing_clustered"
LEGIT_DIR = ROOT_DIR / "samples" / "legit"


def load_prototypes(folder: Path) -> List[bytes]:
    """
    Load all .dom files from a folder as byte arrays.
    
    Args:
        folder: Path to folder containing .dom files
        
    Returns:
        List of DOM prototypes as bytes
    """
    if not folder.exists():
        logger.warning(f"Prototype folder not found: {folder}")
        return []
    
    items = []
    for fn in os.listdir(folder):
        if fn.endswith(".dom"):
            filepath = folder / fn
            try:
                with open(filepath, "rb") as f:
                    data = f.read()
                    if data:  # Only add non-empty files
                        items.append(data)
            except Exception as e:
                logger.error(f"Failed to load prototype {filepath}: {e}")
    
    logger.info(f"Loaded {len(items)} prototypes from {folder}")
    return items


# Load clustered phishing prototypes
PHISH_CLUSTER_1 = load_prototypes(PHISHING_CLUSTERED_DIR / "cluster_1")
PHISH_CLUSTER_2 = load_prototypes(PHISHING_CLUSTERED_DIR / "cluster_2")
PHISH_CLUSTER_3 = load_prototypes(PHISHING_CLUSTERED_DIR / "cluster_3")

# Load legitimate prototypes
LEGIT_PROTOTYPES = load_prototypes(LEGIT_DIR)

# Summary
total_phish = len(PHISH_CLUSTER_1) + len(PHISH_CLUSTER_2) + len(PHISH_CLUSTER_3)
logger.info(f"Clustered prototype summary:")
logger.info(f"  Phishing cluster 1: {len(PHISH_CLUSTER_1)} samples")
logger.info(f"  Phishing cluster 2: {len(PHISH_CLUSTER_2)} samples")
logger.info(f"  Phishing cluster 3: {len(PHISH_CLUSTER_3)} samples")
logger.info(f"  Total phishing: {total_phish} samples")
logger.info(f"  Legitimate: {len(LEGIT_PROTOTYPES)} samples")
