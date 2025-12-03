"""
Training script for phishing detection ML model.

Loads samples, extracts features, and trains a classifier.
"""
import sys
import json
import logging
from pathlib import Path
from typing import List, Tuple
import numpy as np

# Add parent directory to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.features import extract_features
from src.model import PhishingDetectorModel, create_model
from src.config import SAMPLES_DIR, ROOT_DIR

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("train_model")


def load_samples(samples_dir: Path) -> List[Tuple[str, str]]:
    """
    Load all samples from the samples directory.
    
    Args:
        samples_dir: Path to samples directory
        
    Returns:
        List of (html_content, label) tuples
    """
    samples = []
    
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
            
            # Read metadata
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            
            label = meta.get("label", "legit")
            
            # Convert DOM bytes to string (for feature extraction)
            # Note: This is sanitized DOM, but we'll use it for features
            dom_string = dom_bytes.decode("utf-8", errors="ignore")
            
            samples.append((dom_string, label))
            
        except Exception as e:
            logger.error(f"Error loading sample {dom_file.name}: {e}")
    
    # Also load from subdirectories (legit/, phishing/)
    for subdir_name in ["legit", "phishing"]:
        subdir = samples_dir / subdir_name
        if subdir.exists():
            for dom_file in sorted(subdir.glob("*.dom")):
                try:
                    with open(dom_file, "rb") as f:
                        dom_bytes = f.read()
                    
                    # Infer label from directory name
                    label = "phish" if subdir_name == "phishing" else "legit"
                    
                    dom_string = dom_bytes.decode("utf-8", errors="ignore")
                    samples.append((dom_string, label))
                    
                except Exception as e:
                    logger.error(f"Error loading sample {dom_file.name}: {e}")
    
    logger.info(f"Loaded {len(samples)} samples")
    return samples


def extract_features_from_samples(samples: List[Tuple[str, str]]) -> Tuple[np.ndarray, np.ndarray]:
    """
    Extract features from all samples.
    
    Args:
        samples: List of (html_content, label) tuples
        
    Returns:
        Tuple of (X, y) where X is feature matrix and y is labels
    """
    X = []
    y = []
    
    logger.info("Extracting features from samples...")
    
    for i, (html, label) in enumerate(samples):
        try:
            # Extract features
            features = extract_features(html)
            
            # Convert to array in correct order
            feature_vector = []
            from src.model import FEATURE_ORDER
            for feature_name in FEATURE_ORDER:
                value = features.get(feature_name, 0.0)
                feature_vector.append(float(value))
            
            X.append(feature_vector)
            
            # Convert label to binary (0 = legit, 1 = phish)
            y.append(1 if label == "phish" else 0)
            
            if (i + 1) % 10 == 0:
                logger.info(f"Processed {i + 1}/{len(samples)} samples")
                
        except Exception as e:
            logger.error(f"Error extracting features from sample {i}: {e}")
            continue
    
    logger.info(f"Extracted features from {len(X)} samples")
    return np.array(X), np.array(y)


def evaluate_model(model: PhishingDetectorModel, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, float]:
    """
    Evaluate model and return metrics.
    
    Args:
        model: Trained model
        X_test: Test features
        y_test: Test labels
        
    Returns:
        Dictionary of metrics
    """
    try:
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
        
        # Scale test features
        X_test_scaled = model.scaler.transform(X_test)
        
        # Predict
        y_pred = model.model.predict(X_test_scaled)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        
        logger.info("\n" + "="*60)
        logger.info("Model Evaluation Metrics:")
        logger.info("="*60)
        logger.info(f"Accuracy:  {accuracy:.4f}")
        logger.info(f"Precision: {precision:.4f}")
        logger.info(f"Recall:    {recall:.4f}")
        logger.info(f"F1-Score:  {f1:.4f}")
        logger.info("="*60)
        logger.info("\nClassification Report:")
        logger.info(classification_report(y_test, y_pred, target_names=["legit", "phish"]))
        
        return {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1)
        }
    except ImportError:
        logger.warning("scikit-learn metrics not available for detailed evaluation")
        return {}


def main():
    """Main training function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Train phishing detection ML model")
    parser.add_argument(
        "--samples-dir",
        type=str,
        default=str(SAMPLES_DIR),
        help="Path to samples directory"
    )
    parser.add_argument(
        "--model-type",
        type=str,
        default="logistic_regression",
        choices=["logistic_regression", "random_forest"],
        help="Type of classifier to train"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(ROOT_DIR / "models" / "model.pkl"),
        help="Output path for trained model"
    )
    parser.add_argument(
        "--test-split",
        type=float,
        default=0.2,
        help="Fraction of data to use for testing (0.0 to 1.0)"
    )
    
    args = parser.parse_args()
    
    try:
        # Load samples
        samples = load_samples(Path(args.samples_dir))
        
        if len(samples) < 10:
            logger.error(f"Not enough samples ({len(samples)}). Need at least 10 samples for training.")
            sys.exit(1)
        
        # Extract features
        X, y = extract_features_from_samples(samples)
        
        if len(X) == 0:
            logger.error("No features extracted. Check sample files.")
            sys.exit(1)
        
        # Split into train/test
        from sklearn.model_selection import train_test_split
        
        if args.test_split > 0:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=args.test_split, random_state=42, stratify=y
            )
        else:
            X_train, X_test, y_train, y_test = X, X, y, y
        
        logger.info(f"Training set: {len(X_train)} samples")
        logger.info(f"Test set: {len(X_test)} samples")
        logger.info(f"Features: {X_train.shape[1]} features")
        
        # Create and train model
        model = create_model(model_type=args.model_type)
        train_metrics = model.train(X_train, y_train)
        
        # Evaluate on test set
        if args.test_split > 0:
            test_metrics = evaluate_model(model, X_test, y_test)
        else:
            test_metrics = {}
        
        # Save model
        model.save(args.output)
        
        logger.info(f"\nModel saved to: {args.output}")
        logger.info("Training complete!")
        
        return 0
        
    except Exception as e:
        logger.error(f"Training failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    sys.exit(main())


