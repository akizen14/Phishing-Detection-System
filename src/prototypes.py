"""
Prototype Clustering using Farthest Point First (FPF) Algorithm.

Selects K representative prototypes from each class (phishing/legitimate)
by choosing points that are maximally distant from each other.
"""
import json
import random
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import numpy as np

from src.ncd import ncd
from src.config import SAMPLES_DIR, ROOT_DIR

logger = logging.getLogger("prototypes")

# Default number of prototypes per class
DEFAULT_K = 5

# Prototypes directory
PROTOTYPES_DIR = ROOT_DIR / "prototypes"


def load_dom_samples(samples_dir: Path, filter_minimal: bool = False, minimal_threshold: int = 300) -> Tuple[List[Tuple[bytes, str, Dict]], List[Tuple[bytes, str, Dict]]]:
    """
    Load all DOM samples from the samples directory.
    
    Args:
        samples_dir: Path to samples directory
        filter_minimal: If True, exclude extremely small DOMs from prototype building
        minimal_threshold: Size threshold in bytes for minimal DOMs (default: 300)
        
    Returns:
        Tuple of (phishing_samples, legit_samples)
        Each sample is (dom_bytes, label, metadata)
    """
    phish_samples = []
    legit_samples = []
    minimal_count = 0
    
    # Load from main samples directory
    for dom_file in sorted(samples_dir.glob("*.dom")):
        meta_file = dom_file.with_suffix(".meta.json")
        
        if not meta_file.exists():
            logger.warning(f"Missing metadata for {dom_file.name}")
            continue
        
        try:
            # Read DOM bytes
            with open(dom_file, "rb") as f:
                dom_bytes = f.read()
            
            # Filter minimal DOMs if requested (they don't make good prototypes)
            if filter_minimal and len(dom_bytes) < minimal_threshold:
                minimal_count += 1
                continue
            
            # Read metadata
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            
            label = meta.get("label", "legit")
            sample = (dom_bytes, label, meta)
            
            if label == "phish":
                phish_samples.append(sample)
            else:
                legit_samples.append(sample)
                
        except Exception as e:
            logger.error(f"Error loading sample {dom_file.name}: {e}")
    
    # Also load from subdirectories
    for subdir_name, target_list in [("phishing", phish_samples), ("legit", legit_samples)]:
        subdir = samples_dir / subdir_name
        if subdir.exists():
            for dom_file in sorted(subdir.glob("*.dom")):
                try:
                    with open(dom_file, "rb") as f:
                        dom_bytes = f.read()
                    
                    # Filter minimal DOMs if requested
                    if filter_minimal and len(dom_bytes) < minimal_threshold:
                        minimal_count += 1
                        continue
                    
                    # Infer label from directory name
                    label = "phish" if subdir_name == "phishing" else "legit"
                    meta = {"url": dom_file.stem, "label": label}
                    
                    target_list.append((dom_bytes, label, meta))
                    
                except Exception as e:
                    logger.error(f"Error loading sample {dom_file.name}: {e}")
    
    if filter_minimal and minimal_count > 0:
        logger.info(f"Filtered out {minimal_count} minimal DOM samples (< {minimal_threshold} bytes) from prototype building")
    
    logger.info(f"Loaded {len(phish_samples)} phishing samples and {len(legit_samples)} legitimate samples")
    return phish_samples, legit_samples


def compute_distance_matrix(samples: List[Tuple[bytes, str, Dict]]) -> np.ndarray:
    """
    Compute pairwise NCD distance matrix for samples.
    
    Args:
        samples: List of (dom_bytes, label, metadata) tuples
        
    Returns:
        NxN distance matrix where matrix[i][j] = NCD(samples[i], samples[j])
    """
    n = len(samples)
    logger.info(f"Computing {n}x{n} distance matrix...")
    
    # Initialize matrix
    matrix = np.zeros((n, n))
    
    # Compute pairwise distances (symmetric, so we can optimize)
    for i in range(n):
        for j in range(i + 1, n):
            dom_i = samples[i][0]
            dom_j = samples[j][0]
            distance = ncd(dom_i, dom_j)
            matrix[i][j] = distance
            matrix[j][i] = distance  # Symmetric
        
        # Diagonal is 0 (distance to self)
        matrix[i][i] = 0.0
        
        if (i + 1) % 10 == 0:
            logger.info(f"Computed distances for {i + 1}/{n} samples")
    
    logger.info("Distance matrix computation complete")
    return matrix


def run_fpf_clustering(samples: List[Tuple[bytes, str, Dict]], k: int, distance_matrix: Optional[np.ndarray] = None) -> List[int]:
    """
    Run Farthest Point First (FPF) clustering to select K prototypes.
    
    Algorithm:
    1. Randomly select first prototype
    2. For each remaining iteration:
       - Select the point that is farthest from all previously selected prototypes
       - Distance = minimum distance to any selected prototype
    
    Args:
        samples: List of (dom_bytes, label, metadata) tuples
        k: Number of prototypes to select
        distance_matrix: Pre-computed distance matrix (optional, will compute if None)
        
    Returns:
        List of indices of selected prototypes
    """
    n = len(samples)
    
    if k >= n:
        logger.warning(f"K ({k}) >= number of samples ({n}), returning all samples")
        return list(range(n))
    
    if k <= 0:
        raise ValueError(f"K must be positive, got {k}")
    
    logger.info(f"Running FPF clustering: selecting {k} prototypes from {n} samples")
    
    # Compute distance matrix if not provided
    if distance_matrix is None:
        distance_matrix = compute_distance_matrix(samples)
    
    # Step 1: Randomly select first prototype
    selected = [random.randint(0, n - 1)]
    logger.info(f"Selected first prototype (random): index {selected[0]}")
    
    # Step 2: Iteratively select farthest points
    for iteration in range(1, k):
        # For each unselected point, find minimum distance to selected prototypes
        min_distances = []
        
        for i in range(n):
            if i in selected:
                continue
            
            # Find minimum distance to any selected prototype
            min_dist = min(distance_matrix[i][j] for j in selected)
            min_distances.append((i, min_dist))
        
        # Select the point with maximum minimum distance
        if not min_distances:
            break
        
        farthest_idx, farthest_dist = max(min_distances, key=lambda x: x[1])
        selected.append(farthest_idx)
        logger.info(f"Iteration {iteration + 1}: Selected prototype {farthest_idx} (min distance: {farthest_dist:.4f})")
    
    logger.info(f"FPF clustering complete: selected {len(selected)} prototypes")
    return selected


def save_prototypes(prototypes: List[Tuple[bytes, str, Dict]], label: str, output_dir: Path) -> List[str]:
    """
    Save prototypes to disk.
    
    Args:
        prototypes: List of (dom_bytes, label, metadata) tuples
        label: Class label ("phish" or "legit")
        output_dir: Directory to save prototypes
        
    Returns:
        List of saved prototype filenames
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    
    saved_files = []
    
    for idx, (dom_bytes, _, meta) in enumerate(prototypes):
        # Generate filename
        base_name = f"{label}_prototype_{idx + 1:02d}"
        dom_file = output_dir / f"{base_name}.dom"
        meta_file = output_dir / f"{base_name}.meta.json"
        
        # Save DOM bytes
        with open(dom_file, "wb") as f:
            f.write(dom_bytes)
        
        # Save metadata
        meta_data = {
            "label": label,
            "prototype_index": idx + 1,
            "url": meta.get("url", "unknown"),
            "size": len(dom_bytes),
            "source": meta
        }
        
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(meta_data, f, indent=2)
        
        saved_files.append(base_name)
    
    logger.info(f"Saved {len(saved_files)} {label} prototypes to {output_dir}")
    return saved_files


def build_prototypes(samples_dir: Path = None, k: int = DEFAULT_K, output_dir: Path = None, filter_minimal: bool = True, minimal_threshold: int = 300) -> Dict:
    """
    Build prototypes using FPF clustering.
    
    Args:
        samples_dir: Path to samples directory (default: SAMPLES_DIR)
        k: Number of prototypes per class (default: 5)
        output_dir: Directory to save prototypes (default: PROTOTYPES_DIR)
        filter_minimal: If True, exclude minimal DOMs from prototype building (default: True)
        minimal_threshold: Size threshold in bytes for minimal DOMs (default: 300)
        
    Returns:
        Dictionary with build summary
    """
    if samples_dir is None:
        samples_dir = SAMPLES_DIR
    if output_dir is None:
        output_dir = PROTOTYPES_DIR
    
    logger.info(f"Building prototypes: K={k}, samples_dir={samples_dir}, output_dir={output_dir}, filter_minimal={filter_minimal}")
    
    # Load samples (optionally filtering minimal DOMs)
    phish_samples, legit_samples = load_dom_samples(samples_dir, filter_minimal=filter_minimal, minimal_threshold=minimal_threshold)
    
    if len(phish_samples) < k:
        logger.warning(f"Only {len(phish_samples)} phishing samples available, using all as prototypes")
        k_phish = len(phish_samples)
    else:
        k_phish = k
    
    if len(legit_samples) < k:
        logger.warning(f"Only {len(legit_samples)} legitimate samples available, using all as prototypes")
        k_legit = len(legit_samples)
    else:
        k_legit = k
    
    # Build prototypes for each class
    results = {
        "phishing": {"k": k_phish, "samples": len(phish_samples), "prototypes": []},
        "legitimate": {"k": k_legit, "samples": len(legit_samples), "prototypes": []}
    }
    
    # Phishing prototypes
    if phish_samples:
        logger.info(f"Selecting {k_phish} phishing prototypes from {len(phish_samples)} samples")
        phish_distance_matrix = compute_distance_matrix(phish_samples)
        phish_indices = run_fpf_clustering(phish_samples, k_phish, phish_distance_matrix)
        phish_prototypes = [phish_samples[i] for i in phish_indices]
        
        phish_dir = output_dir / "phishing"
        phish_files = save_prototypes(phish_prototypes, "phish", phish_dir)
        results["phishing"]["prototypes"] = phish_files
        results["phishing"]["indices"] = phish_indices
    
    # Legitimate prototypes
    if legit_samples:
        logger.info(f"Selecting {k_legit} legitimate prototypes from {len(legit_samples)} samples")
        legit_distance_matrix = compute_distance_matrix(legit_samples)
        legit_indices = run_fpf_clustering(legit_samples, k_legit, legit_distance_matrix)
        legit_prototypes = [legit_samples[i] for i in legit_indices]
        
        legit_dir = output_dir / "legitimate"
        legit_files = save_prototypes(legit_prototypes, "legit", legit_dir)
        results["legitimate"]["prototypes"] = legit_files
        results["legitimate"]["indices"] = legit_indices
    
    logger.info("Prototype building complete")
    return results


def load_prototypes(prototypes_dir: Path = None) -> Tuple[List[bytes], List[bytes]]:
    """
    Load prototypes from disk.
    
    Args:
        prototypes_dir: Directory containing prototypes (default: PROTOTYPES_DIR)
        
    Returns:
        Tuple of (phishing_prototypes, legitimate_prototypes)
        Each is a list of DOM bytes
    """
    if prototypes_dir is None:
        prototypes_dir = PROTOTYPES_DIR
    
    phish_prototypes = []
    legit_prototypes = []
    
    # Load phishing prototypes
    phish_dir = prototypes_dir / "phishing"
    if phish_dir.exists():
        for dom_file in sorted(phish_dir.glob("*.dom")):
            try:
                with open(dom_file, "rb") as f:
                    phish_prototypes.append(f.read())
            except Exception as e:
                logger.error(f"Error loading prototype {dom_file.name}: {e}")
    
    # Load legitimate prototypes
    legit_dir = prototypes_dir / "legitimate"
    if legit_dir.exists():
        for dom_file in sorted(legit_dir.glob("*.dom")):
            try:
                with open(dom_file, "rb") as f:
                    legit_prototypes.append(f.read())
            except Exception as e:
                logger.error(f"Error loading prototype {dom_file.name}: {e}")
    
    logger.info(f"Loaded {len(phish_prototypes)} phishing prototypes and {len(legit_prototypes)} legitimate prototypes")
    return phish_prototypes, legit_prototypes
