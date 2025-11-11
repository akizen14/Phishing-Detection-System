"""
DOM prototype loader for NCD-based phishing detection.

Loads pre-extracted DOM samples from disk to use as reference prototypes
for similarity comparison.
"""
import os
import logging
from pathlib import Path
from typing import List

from src.config import ROOT_DIR

logger = logging.getLogger("prototypes")

# Prototype directories
PHISHING_DIR = ROOT_DIR / "samples" / "phishing"
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


# Load prototypes at module import time
PHISH_PROTOTYPES = load_prototypes(PHISHING_DIR)
LEGIT_PROTOTYPES = load_prototypes(LEGIT_DIR)

logger.info(f"Prototype summary: {len(PHISH_PROTOTYPES)} phishing, {len(LEGIT_PROTOTYPES)} legit")
