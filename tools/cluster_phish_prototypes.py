"""
Automatic Structural Clustering of Phishing Prototypes Using NCD

Uses Farthest-Point-First clustering to group phishing DOM prototypes
into structural families based on NCD distance.

Usage:
    python tools/cluster_phish_prototypes.py
"""
import sys
import shutil
import numpy as np
from pathlib import Path

# Add parent directory to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.ncd import ncd
from src.config import ROOT_DIR

# Directories
PHISHING_DIR = ROOT_DIR / "samples" / "phishing"
CLUSTERED_DIR = ROOT_DIR / "samples" / "phishing_clustered"

# Clustering parameters
MAX_CLUSTERS = 4
MIN_CLUSTERS = 2


def load_phishing_samples(phishing_dir: Path):
    """
    Load all phishing DOM samples.
    
    Returns:
        List of tuples (filename, dom_bytes)
    """
    samples = []
    for dom_file in sorted(phishing_dir.glob("*.dom")):
        with open(dom_file, "rb") as f:
            samples.append((dom_file.name, f.read()))
    return samples


def compute_distance_matrix(samples):
    """
    Compute pairwise NCD distance matrix.
    
    Args:
        samples: List of (filename, dom_bytes) tuples
        
    Returns:
        numpy array of distances
    """
    n = len(samples)
    distances = np.zeros((n, n))
    
    print(f"Computing {n}x{n} = {n*n} pairwise NCD distances...")
    print("This may take several minutes...")
    print()
    
    for i in range(n):
        for j in range(i+1, n):
            dist = ncd(samples[i][1], samples[j][1])
            distances[i][j] = dist
            distances[j][i] = dist
            
            if (i * n + j) % 10 == 0:
                progress = ((i * n + j) / (n * n)) * 100
                print(f"  Progress: {progress:.1f}% ({i*n+j}/{n*n} pairs)", end='\r')
    
    print(f"  Progress: 100.0% ({n*n}/{n*n} pairs)  ")
    print()
    return distances


def farthest_point_clustering(distances, samples, max_clusters=4):
    """
    Farthest-Point-First clustering algorithm.
    
    Args:
        distances: NxN distance matrix
        samples: List of (filename, dom_bytes) tuples
        max_clusters: Maximum number of clusters
        
    Returns:
        List of cluster assignments (one per sample)
    """
    n = len(samples)
    
    # Start with sample having largest average distance
    avg_distances = distances.mean(axis=1)
    first_center_idx = np.argmax(avg_distances)
    
    centers = [first_center_idx]
    print(f"Initial center: Sample {first_center_idx} ({samples[first_center_idx][0]})")
    print(f"  Average distance: {avg_distances[first_center_idx]:.4f}")
    print()
    
    # Iteratively add centers
    for k in range(2, max_clusters + 1):
        # For each sample, find distance to closest center
        min_dist_to_centers = np.full(n, np.inf)
        for center_idx in centers:
            min_dist_to_centers = np.minimum(min_dist_to_centers, distances[center_idx])
        
        # Pick sample farthest from all existing centers
        new_center_idx = np.argmax(min_dist_to_centers)
        
        # Calculate variance reduction
        old_variance = np.var(min_dist_to_centers)
        
        # Simulate adding this center
        test_min_dist = np.minimum(min_dist_to_centers, distances[new_center_idx])
        new_variance = np.var(test_min_dist)
        variance_reduction = old_variance - new_variance
        
        print(f"Cluster {k}:")
        print(f"  Candidate center: Sample {new_center_idx} ({samples[new_center_idx][0]})")
        print(f"  Distance to nearest center: {min_dist_to_centers[new_center_idx]:.4f}")
        print(f"  Variance reduction: {variance_reduction:.6f}")
        
        # Stop if variance reduction is too small
        if variance_reduction < 0.001 and k >= MIN_CLUSTERS:
            print(f"  -> Stopping: minimal variance reduction")
            print()
            break
        
        centers.append(new_center_idx)
        print(f"  -> Added as cluster center")
        print()
    
    # Assign each sample to closest center
    assignments = []
    for i in range(n):
        closest_center = min(range(len(centers)), key=lambda c: distances[i][centers[c]])
        assignments.append(closest_center)
    
    return assignments, centers


def create_clustered_directories(samples, assignments, centers, output_dir: Path):
    """
    Create cluster directories and copy samples.
    
    Args:
        samples: List of (filename, dom_bytes) tuples
        assignments: Cluster assignment for each sample
        centers: List of center indices
        output_dir: Output directory for clusters
    """
    # Clear existing clustered directory
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)
    
    # Create cluster directories
    num_clusters = len(centers)
    for cluster_id in range(num_clusters):
        cluster_dir = output_dir / f"cluster_{cluster_id + 1}"
        cluster_dir.mkdir()
    
    # Copy samples to clusters
    cluster_counts = [0] * num_clusters
    for i, (filename, dom_bytes) in enumerate(samples):
        cluster_id = assignments[i]
        cluster_dir = output_dir / f"cluster_{cluster_id + 1}"
        
        # Copy file
        src_file = PHISHING_DIR / filename
        dst_file = cluster_dir / filename
        shutil.copy2(src_file, dst_file)
        
        cluster_counts[cluster_id] += 1
    
    return cluster_counts


def analyze_clusters(samples, assignments, centers, distances):
    """
    Analyze cluster quality.
    
    Args:
        samples: List of (filename, dom_bytes) tuples
        assignments: Cluster assignment for each sample
        centers: List of center indices
        distances: Distance matrix
    """
    num_clusters = len(centers)
    
    print("=" * 70)
    print("CLUSTER ANALYSIS")
    print("=" * 70)
    print()
    
    for cluster_id in range(num_clusters):
        cluster_samples = [i for i, a in enumerate(assignments) if a == cluster_id]
        center_idx = centers[cluster_id]
        
        print(f"Cluster {cluster_id + 1}:")
        print(f"  Center: {samples[center_idx][0]}")
        print(f"  Size: {len(cluster_samples)} samples")
        
        # Intra-cluster distances
        if len(cluster_samples) > 1:
            intra_distances = []
            for i in cluster_samples:
                for j in cluster_samples:
                    if i < j:
                        intra_distances.append(distances[i][j])
            
            if intra_distances:
                print(f"  Intra-cluster distance:")
                print(f"    Min: {min(intra_distances):.4f}")
                print(f"    Max: {max(intra_distances):.4f}")
                print(f"    Avg: {np.mean(intra_distances):.4f}")
        
        print(f"  Samples:")
        for i in cluster_samples:
            dist_to_center = distances[i][center_idx]
            print(f"    - {samples[i][0]} (dist: {dist_to_center:.4f})")
        print()


def main():
    """Main entry point."""
    print("=" * 70)
    print("Automatic Structural Clustering of Phishing Prototypes")
    print("=" * 70)
    print()
    
    # Load samples
    print(f"Loading phishing samples from: {PHISHING_DIR}")
    samples = load_phishing_samples(PHISHING_DIR)
    print(f"Loaded {len(samples)} phishing samples")
    print()
    
    if len(samples) < MIN_CLUSTERS:
        print(f"ERROR: Need at least {MIN_CLUSTERS} samples for clustering")
        return
    
    # Compute distance matrix
    distances = compute_distance_matrix(samples)
    
    # Perform clustering
    print("=" * 70)
    print("FARTHEST-POINT-FIRST CLUSTERING")
    print("=" * 70)
    print()
    
    assignments, centers = farthest_point_clustering(distances, samples, MAX_CLUSTERS)
    
    print(f"Final number of clusters: {len(centers)}")
    print()
    
    # Create directories and copy files
    print("=" * 70)
    print("CREATING CLUSTER DIRECTORIES")
    print("=" * 70)
    print()
    
    cluster_counts = create_clustered_directories(samples, assignments, centers, CLUSTERED_DIR)
    
    for cluster_id, count in enumerate(cluster_counts):
        cluster_dir = CLUSTERED_DIR / f"cluster_{cluster_id + 1}"
        print(f"Cluster {cluster_id + 1}: {count} samples -> {cluster_dir}")
    print()
    
    # Analyze clusters
    analyze_clusters(samples, assignments, centers, distances)
    
    # Summary
    print("=" * 70)
    print("CLUSTERING COMPLETE")
    print("=" * 70)
    print()
    print(f"Output directory: {CLUSTERED_DIR}")
    print(f"Number of clusters: {len(centers)}")
    print(f"Total samples: {len(samples)}")
    print()
    print("Next steps:")
    print("  1. Review cluster assignments above")
    print("  2. System will use clustered prototypes for classification")
    print("  3. Run threshold tuning after updating detector")
    print()


if __name__ == "__main__":
    main()
