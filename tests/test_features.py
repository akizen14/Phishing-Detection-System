"""
Unit tests for feature extraction module.
"""
import pytest
from src.features import (
    extract_features,
    extract_tag_features,
    extract_structure_features,
    compute_ncd_to_prototypes,
    calculate_shannon_entropy,
    _get_empty_features
)


class TestTagFeatures:
    """Test tag-based feature extraction."""
    
    def test_simple_html(self):
        """Test feature extraction from simple HTML."""
        html = "<html><head><title>Test</title></head><body><p>Hello</p></body></html>"
        features = extract_tag_features(html)
        
        assert features["total_tag_count"] == 5  # html, head, title, body, p
        assert features["unique_tag_count"] == 5
        assert features["depth_of_dom_tree"] == 3  # html -> head -> title
        assert features["count_form"] == 0.0
        assert features["count_input"] == 0.0
    
    def test_form_tags(self):
        """Test counting of form-related tags."""
        html = """
        <html>
            <body>
                <form>
                    <input type="text" />
                    <input type="password" />
                    <button>Submit</button>
                </form>
            </body>
        </html>
        """
        features = extract_tag_features(html)
        
        assert features["count_form"] == 1.0
        assert features["count_input"] == 2.0
    
    def test_specific_tags(self):
        """Test counting of specific tags."""
        html = """
        <html>
            <head>
                <meta charset="utf-8" />
                <link rel="stylesheet" href="style.css" />
                <script src="app.js"></script>
            </head>
            <body>
                <img src="logo.png" />
                <iframe src="embed.html"></iframe>
            </body>
        </html>
        """
        features = extract_tag_features(html)
        
        assert features["count_meta"] == 1.0
        assert features["count_link"] == 1.0
        assert features["count_script"] == 1.0
        assert features["count_img"] == 1.0
        assert features["count_iframe"] == 1.0
    
    def test_empty_html(self):
        """Test feature extraction from empty HTML."""
        html = ""
        features = extract_tag_features(html)
        
        assert features["total_tag_count"] == 0.0
        assert features["unique_tag_count"] == 0.0
        assert features["depth_of_dom_tree"] == 0.0
    
    def test_nested_structure(self):
        """Test depth calculation for nested structures."""
        html = "<div><div><div><p>Deep</p></div></div></div>"
        features = extract_tag_features(html)
        
        assert features["depth_of_dom_tree"] >= 4  # div -> div -> div -> p
        assert features["total_tag_count"] == 4


class TestStructureFeatures:
    """Test structure-based feature extraction."""
    
    def test_dom_entropy(self):
        """Test Shannon entropy calculation."""
        html = "<html><head><title>Test</title></head><body><p>Hello</p></body></html>"
        features = extract_structure_features(html, html.encode("utf-8"))
        
        assert features["dom_entropy"] >= 0.0
        assert features["dom_token_count"] > 0.0
        assert features["dom_length_bytes"] > 0.0
    
    def test_ratio_interactive_tags(self):
        """Test ratio of interactive tags."""
        html = """
        <html>
            <body>
                <form>
                    <input type="text" />
                    <button>Submit</button>
                </form>
                <p>Text</p>
                <div>Content</div>
            </body>
        </html>
        """
        features = extract_structure_features(html, html.encode("utf-8"))
        
        # Should have some interactive tags (form, input, button)
        assert features["ratio_interactive_tags"] >= 0.0
        assert features["ratio_interactive_tags"] <= 1.0
    
    def test_dom_length(self):
        """Test DOM length calculation."""
        html = "<html><body><p>Test</p></body></html>"
        features = extract_structure_features(html, html.encode("utf-8"))
        
        assert features["dom_length_bytes"] == len(html.encode("utf-8"))


class TestShannonEntropy:
    """Test Shannon entropy calculation."""
    
    def test_entropy_uniform(self):
        """Test entropy with uniform distribution."""
        # Uniform distribution should have high entropy
        sequence = "abcabcabc"
        entropy = calculate_shannon_entropy(sequence)
        assert entropy > 0.0
    
    def test_entropy_repetitive(self):
        """Test entropy with repetitive sequence."""
        # Repetitive sequence should have lower entropy
        sequence = "aaaaaa"
        entropy = calculate_shannon_entropy(sequence)
        assert entropy == 0.0  # All same characters
    
    def test_entropy_empty(self):
        """Test entropy of empty sequence."""
        entropy = calculate_shannon_entropy("")
        assert entropy == 0.0


class TestNCDFeatures:
    """Test NCD-based feature extraction."""
    
    def test_ncd_features_structure(self):
        """Test that NCD features have correct structure."""
        dom_bytes = b"<html><body><p>Test</p></body></html>"
        features = compute_ncd_to_prototypes(dom_bytes)
        
        # Check all expected keys exist
        assert "ncd_phish_cluster_1_min" in features
        assert "ncd_phish_cluster_1_avg" in features
        assert "ncd_phish_cluster_2_min" in features
        assert "ncd_phish_cluster_2_avg" in features
        assert "ncd_phish_cluster_3_min" in features
        assert "ncd_phish_cluster_3_avg" in features
        assert "ncd_legit_min" in features
        assert "ncd_legit_avg" in features
        assert "ncd_phish_best" in features
        assert "ncd_phish_avg" in features
        
        # Check values are in valid range (0.0 to 1.0+)
        for key, value in features.items():
            assert isinstance(value, float)
            assert value >= 0.0
    
    def test_ncd_features_values(self):
        """Test that NCD features have reasonable values."""
        dom_bytes = b"<html><body><p>Test</p></body></html>"
        features = compute_ncd_to_prototypes(dom_bytes)
        
        # Best should be minimum of all cluster mins
        assert features["ncd_phish_best"] <= features["ncd_phish_cluster_1_min"]
        assert features["ncd_phish_best"] <= features["ncd_phish_cluster_2_min"]
        assert features["ncd_phish_best"] <= features["ncd_phish_cluster_3_min"]


class TestExtractFeatures:
    """Test main feature extraction function."""
    
    def test_complete_feature_extraction(self):
        """Test that extract_features returns all feature categories."""
        html = """
        <html>
            <head>
                <title>Test Page</title>
                <meta charset="utf-8" />
            </head>
            <body>
                <form>
                    <input type="text" />
                    <button>Submit</button>
                </form>
                <p>Content</p>
            </body>
        </html>
        """
        features = extract_features(html)
        
        # Check tag features
        assert "total_tag_count" in features
        assert "unique_tag_count" in features
        assert "depth_of_dom_tree" in features
        assert "count_form" in features
        assert "count_input" in features
        
        # Check structure features
        assert "dom_entropy" in features
        assert "dom_token_count" in features
        assert "dom_length_bytes" in features
        assert "ratio_interactive_tags" in features
        
        # Check NCD features
        assert "ncd_phish_best" in features
        assert "ncd_legit_min" in features
        
        # Verify all values are floats
        for key, value in features.items():
            assert isinstance(value, float), f"{key} is not a float: {type(value)}"
    
    def test_empty_dom(self):
        """Test feature extraction with empty DOM."""
        features = extract_features("")
        
        # Should return empty features structure
        assert isinstance(features, dict)
        assert len(features) > 0  # Should have all keys with default values
    
    def test_invalid_html(self):
        """Test feature extraction with invalid HTML."""
        html = "<invalid><unclosed>"
        features = extract_features(html)
        
        # Should still return features (BeautifulSoup is forgiving)
        assert isinstance(features, dict)
        assert "total_tag_count" in features


class TestEmptyFeatures:
    """Test empty features function."""
    
    def test_empty_features_structure(self):
        """Test that empty features has all required keys."""
        empty = _get_empty_features()
        
        # Check all feature categories are present
        assert "total_tag_count" in empty
        assert "dom_entropy" in empty
        assert "ncd_phish_best" in empty
        
        # Check all values are floats
        for value in empty.values():
            assert isinstance(value, float)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


