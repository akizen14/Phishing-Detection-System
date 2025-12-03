"""
Unit tests for ML model module.
"""
import pytest
import numpy as np
import tempfile
from pathlib import Path

try:
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

if SKLEARN_AVAILABLE:
    from src.model import PhishingDetectorModel, create_model, FEATURE_ORDER


@pytest.mark.skipif(not SKLEARN_AVAILABLE, reason="scikit-learn not installed")
class TestPhishingDetectorModel:
    """Test PhishingDetectorModel class."""
    
    def test_create_logistic_regression(self):
        """Test creating Logistic Regression model."""
        model = create_model("logistic_regression")
        assert model.model_type == "logistic_regression"
        assert model.model is not None
        assert not model.is_trained
    
    def test_create_random_forest(self):
        """Test creating Random Forest model."""
        model = create_model("random_forest")
        assert model.model_type == "random_forest"
        assert model.model is not None
        assert not model.is_trained
    
    def test_train_model(self):
        """Test training a model on synthetic data."""
        model = create_model("logistic_regression")
        
        # Create synthetic training data (25 features - all FEATURE_ORDER)
        X = np.array([
            [10, 5, 3, 1.5, 1, 2, 0, 1, 0, 0, 1, 2.5, 15, 500, 0.2, 0.3, 0.35, 0.4, 0.45, 0.5, 0.6, 0.7, 0.3, 0.4, 0.35],
            [20, 8, 5, 2.0, 0, 0, 1, 3, 1, 2, 2, 3.0, 25, 1000, 0.1, 0.2, 0.25, 0.3, 0.35, 0.4, 0.5, 0.6, 0.2, 0.3, 0.25],
            [15, 6, 4, 1.8, 0, 1, 0, 2, 0, 1, 1, 2.8, 20, 750, 0.15, 0.25, 0.3, 0.35, 0.4, 0.45, 0.55, 0.65, 0.25, 0.35, 0.3],
        ])
        y = np.array([1, 0, 1])  # phish, legit, phish
        
        metrics = model.train(X, y)
        
        assert model.is_trained
        assert "training_accuracy" in metrics
        assert metrics["n_samples"] == 3
        assert metrics["n_features"] == 25
    
    def test_predict(self):
        """Test prediction on trained model."""
        model = create_model("logistic_regression")
        
        # Train on synthetic data (25 features)
        X = np.array([
            [10, 5, 3, 1.5, 1, 2, 0, 1, 0, 0, 1, 2.5, 15, 500, 0.2, 0.3, 0.35, 0.4, 0.45, 0.5, 0.6, 0.7, 0.3, 0.4, 0.35],
            [20, 8, 5, 2.0, 0, 0, 1, 3, 1, 2, 2, 3.0, 25, 1000, 0.1, 0.2, 0.25, 0.3, 0.35, 0.4, 0.5, 0.6, 0.2, 0.3, 0.25],
        ])
        y = np.array([1, 0])
        model.train(X, y)
        
        # Create features dictionary (all 25 features)
        features = {
            "total_tag_count": 10.0,
            "unique_tag_count": 5.0,
            "depth_of_dom_tree": 3.0,
            "average_children_per_node": 1.5,
            "count_form": 1.0,
            "count_input": 2.0,
            "count_script": 0.0,
            "count_img": 1.0,
            "count_iframe": 0.0,
            "count_link": 0.0,
            "count_meta": 1.0,
            "dom_entropy": 2.5,
            "dom_token_count": 15.0,
            "dom_length_bytes": 500.0,
            "ratio_interactive_tags": 0.2,
            "ncd_phish_cluster_1_min": 0.3,
            "ncd_phish_cluster_1_avg": 0.35,
            "ncd_phish_cluster_2_min": 0.4,
            "ncd_phish_cluster_2_avg": 0.45,
            "ncd_phish_cluster_3_min": 0.5,
            "ncd_phish_cluster_3_avg": 0.6,
            "ncd_legit_min": 0.7,
            "ncd_legit_avg": 0.3,
            "ncd_phish_best": 0.4,
            "ncd_phish_avg": 0.35
        }
        
        prediction = model.predict(features)
        
        assert "label" in prediction
        assert prediction["label"] in ["phish", "legit"]
        assert "probability" in prediction
        assert 0.0 <= prediction["probability"] <= 1.0
        assert "confidence" in prediction
        assert prediction["confidence"] in ["low", "medium", "high"]
    
    def test_save_and_load(self):
        """Test saving and loading a model."""
        model = create_model("logistic_regression")
        
        # Train on synthetic data (25 features)
        X = np.array([
            [10, 5, 3, 1.5, 1, 2, 0, 1, 0, 0, 1, 2.5, 15, 500, 0.2, 0.3, 0.35, 0.4, 0.45, 0.5, 0.6, 0.7, 0.3, 0.4, 0.35],
            [20, 8, 5, 2.0, 0, 0, 1, 3, 1, 2, 2, 3.0, 25, 1000, 0.1, 0.2, 0.25, 0.3, 0.35, 0.4, 0.5, 0.6, 0.2, 0.3, 0.25],
        ])
        y = np.array([1, 0])
        model.train(X, y)
        
        # Save to temporary file
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as tmp:
            tmp_path = tmp.name
        
        try:
            model.save(tmp_path)
            assert Path(tmp_path).exists()
            
            # Load model
            loaded_model = PhishingDetectorModel.load(tmp_path)
            
            assert loaded_model.is_trained
            assert loaded_model.model_type == "logistic_regression"
            
            # Test that loaded model can predict
            features = {name: 1.0 for name in FEATURE_ORDER}
            prediction = loaded_model.predict(features)
            assert "label" in prediction
            
        finally:
            # Clean up
            Path(tmp_path).unlink(missing_ok=True)
    
    def test_features_dict_to_array(self):
        """Test conversion of features dict to array."""
        model = create_model("logistic_regression")
        
        features = {name: float(i) for i, name in enumerate(FEATURE_ORDER)}
        array = model._features_dict_to_array(features)
        
        assert len(array) == len(FEATURE_ORDER)
        assert isinstance(array, np.ndarray)
    
    def test_predict_untrained_model(self):
        """Test that prediction fails on untrained model."""
        model = create_model("logistic_regression")
        
        features = {name: 1.0 for name in FEATURE_ORDER}
        
        with pytest.raises(ValueError, match="not trained"):
            model.predict(features)
    
    def test_save_untrained_model(self):
        """Test that saving fails on untrained model."""
        model = create_model("logistic_regression")
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as tmp:
            tmp_path = tmp.name
        
        try:
            with pytest.raises(ValueError, match="not trained"):
                model.save(tmp_path)
        finally:
            Path(tmp_path).unlink(missing_ok=True)


@pytest.mark.skipif(not SKLEARN_AVAILABLE, reason="scikit-learn not installed")
class TestModelFactory:
    """Test model factory function."""
    
    def test_create_model_logistic(self):
        """Test creating logistic regression via factory."""
        model = create_model("logistic_regression")
        assert isinstance(model, PhishingDetectorModel)
        assert model.model_type == "logistic_regression"
    
    def test_create_model_random_forest(self):
        """Test creating random forest via factory."""
        model = create_model("random_forest")
        assert isinstance(model, PhishingDetectorModel)
        assert model.model_type == "random_forest"
    
    def test_invalid_model_type(self):
        """Test that invalid model type raises error."""
        with pytest.raises(ValueError):
            create_model("invalid_type")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

