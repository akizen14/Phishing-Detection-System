"""
Machine Learning Model Interface for Phishing Detection.

Supports scikit-learn classifiers (Logistic Regression, Random Forest)
for classification based on extracted features.
"""
import pickle
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import numpy as np

try:
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logging.warning("scikit-learn not installed. ML features will be unavailable.")

logger = logging.getLogger("model")

# Feature order (must match features.py output order)
FEATURE_ORDER = [
    "total_tag_count",
    "unique_tag_count",
    "depth_of_dom_tree",
    "average_children_per_node",
    "count_form",
    "count_input",
    "count_script",
    "count_img",
    "count_iframe",
    "count_link",
    "count_meta",
    "dom_entropy",
    "dom_token_count",
    "dom_length_bytes",
    "ratio_interactive_tags",
    "ncd_phish_cluster_1_min",
    "ncd_phish_cluster_1_avg",
    "ncd_phish_cluster_2_min",
    "ncd_phish_cluster_2_avg",
    "ncd_phish_cluster_3_min",
    "ncd_phish_cluster_3_avg",
    "ncd_legit_min",
    "ncd_legit_avg",
    "ncd_phish_best",
    "ncd_phish_avg"
]  # Total: 25 features


class PhishingDetectorModel:
    """
    ML model wrapper for phishing detection.
    
    Supports Logistic Regression and Random Forest classifiers.
    """
    
    def __init__(self, model_type: str = "logistic_regression"):
        """
        Initialize the model.
        
        Args:
            model_type: Type of classifier ("logistic_regression" or "random_forest")
        """
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn is required for ML features. Install with: pip install scikit-learn")
        
        self.model_type = model_type
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_order = FEATURE_ORDER
        
        if model_type == "logistic_regression":
            self.model = LogisticRegression(
                max_iter=1000,
                random_state=42,
                class_weight="balanced"  # Handle imbalanced datasets
            )
        elif model_type == "random_forest":
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                class_weight="balanced"
            )
        else:
            raise ValueError(f"Unknown model type: {model_type}. Use 'logistic_regression' or 'random_forest'")
    
    def train(self, X: np.ndarray, y: np.ndarray) -> Dict[str, float]:
        """
        Train the model on feature matrix X and labels y.
        
        Args:
            X: Feature matrix (n_samples, n_features)
            y: Labels (n_samples,) - 0 for legit, 1 for phish
            
        Returns:
            Dictionary with training metrics
        """
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn is required")
        
        logger.info(f"Training {self.model_type} model on {len(X)} samples")
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        self.model.fit(X_scaled, y)
        self.is_trained = True
        
        # Calculate training accuracy
        train_score = self.model.score(X_scaled, y)
        
        logger.info(f"Model trained. Training accuracy: {train_score:.4f}")
        
        return {
            "training_accuracy": float(train_score),
            "n_samples": len(X),
            "n_features": X.shape[1]
        }
    
    def predict(self, features_dict: Dict[str, float]) -> Dict[str, any]:
        """
        Predict classification from features dictionary.
        
        Args:
            features_dict: Dictionary of features (from extract_features)
            
        Returns:
            Dictionary with prediction, probability, and label
        """
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() first or load a saved model.")
        
        # Convert features dict to array in correct order
        feature_vector = self._features_dict_to_array(features_dict)
        
        # Scale features
        feature_vector_scaled = self.scaler.transform([feature_vector])
        
        # Predict
        prediction = self.model.predict(feature_vector_scaled)[0]
        probabilities = self.model.predict_proba(feature_vector_scaled)[0]
        
        # Get probability of phishing class (class 1)
        phish_probability = float(probabilities[1])
        legit_probability = float(probabilities[0])
        
        # Convert to label
        label = "phish" if prediction == 1 else "legit"
        
        return {
            "label": label,
            "probability": phish_probability,
            "legit_probability": legit_probability,
            "confidence": "high" if max(probabilities) > 0.8 else ("medium" if max(probabilities) > 0.6 else "low")
        }
    
    def _features_dict_to_array(self, features_dict: Dict[str, float]) -> np.ndarray:
        """
        Convert features dictionary to numpy array in correct order.
        
        Args:
            features_dict: Dictionary of features
            
        Returns:
            Numpy array of features in correct order
        """
        feature_array = []
        for feature_name in self.feature_order:
            value = features_dict.get(feature_name, 0.0)
            feature_array.append(float(value))
        return np.array(feature_array)
    
    def save(self, model_path: str) -> None:
        """
        Save the trained model to disk.
        
        Args:
            model_path: Path to save the model (should end with .pkl)
        """
        if not self.is_trained:
            raise ValueError("Model not trained. Cannot save untrained model.")
        
        model_path = Path(model_path)
        model_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save model and scaler together
        model_data = {
            "model": self.model,
            "scaler": self.scaler,
            "model_type": self.model_type,
            "feature_order": self.feature_order
        }
        
        with open(model_path, "wb") as f:
            pickle.dump(model_data, f)
        
        logger.info(f"Model saved to {model_path}")
    
    @classmethod
    def load(cls, model_path: str) -> "PhishingDetectorModel":
        """
        Load a trained model from disk.
        
        Args:
            model_path: Path to the saved model (.pkl file)
            
        Returns:
            Loaded PhishingDetectorModel instance
        """
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn is required")
        
        model_path = Path(model_path)
        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")
        
        with open(model_path, "rb") as f:
            model_data = pickle.load(f)
        
        # Create instance
        instance = cls(model_type=model_data["model_type"])
        instance.model = model_data["model"]
        instance.scaler = model_data["scaler"]
        instance.is_trained = True
        instance.feature_order = model_data.get("feature_order", FEATURE_ORDER)
        
        logger.info(f"Model loaded from {model_path}")
        return instance


def create_model(model_type: str = "logistic_regression") -> PhishingDetectorModel:
    """
    Factory function to create a model instance.
    
    Args:
        model_type: Type of classifier ("logistic_regression" or "random_forest")
        
    Returns:
        PhishingDetectorModel instance
    """
    return PhishingDetectorModel(model_type=model_type)

