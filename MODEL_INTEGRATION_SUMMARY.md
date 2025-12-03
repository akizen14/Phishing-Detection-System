# Machine Learning Model Integration Summary

## Overview

This document summarizes the integration of Machine Learning (ML) models into the phishing detection system. The ML integration provides a hybrid detection approach that combines traditional NCD-based classification with modern machine learning techniques.

## Phase 3, Step 2: Machine Learning Model Integration

### Implementation Date
Completed: [Current Date]

### Components Added

#### 1. ML Model Interface (`src/model.py`)

**Purpose**: Provides a unified interface for ML-based phishing detection.

**Key Features**:
- Supports multiple classifier types:
  - Logistic Regression (default)
  - Random Forest (configurable)
- StandardScaler for feature normalization
- Model persistence (save/load)
- Feature vector conversion from dictionary format

**Class: `PhishingDetectorModel`**

**Methods**:
- `train(X, y)`: Train the model on feature matrix and labels
- `predict(features_dict)`: Predict classification from features dictionary
- `save(model_path)`: Save trained model to disk
- `load(model_path)`: Load a saved model from disk

**Features Used**: 25 features from `src/features.py`:
- 15 structural features (tags, DOM properties, entropy)
- 10 NCD-based features (distances to phishing/legitimate prototypes)

#### 2. Training Script (`tools/train_model.py`)

**Purpose**: Train ML models on collected samples.

**Features**:
- Loads samples from `samples/` directory
- Extracts features for each sample
- Splits data into train/test sets
- Trains model and evaluates performance
- Saves trained model to `models/model.pkl`

**Usage**:
```bash
python tools/train_model.py --samples-dir samples/ --model-type logistic_regression --output models/model.pkl --test-split 0.2
```

**Output Metrics**:
- Accuracy
- Precision
- Recall
- F1-Score
- Classification Report

#### 3. Detector Integration (`src/detector.py`)

**Changes**:
- Added lazy loading of ML model (`_load_ml_model()`)
- Integrated ML prediction into `classify_url_ncd()`
- Implemented hybrid decision logic:
  - If ML confidence ≥ threshold → Use ML result
  - Otherwise → Use NCD result
- Added `final_verdict` and `decision_source` fields

**Hybrid Decision Logic**:
```python
if ml_confidence >= ML_CONFIDENCE_THRESHOLD:
    final_verdict = ml_label
    decision_source = "ml"
else:
    final_verdict = ncd_verdict
    decision_source = "ncd"
```

#### 4. API Updates (`src/api.py`)

**Changes**:
- Updated response to use `final_verdict` (from hybrid decision)
- Added `ml_prediction` field to response when ML is enabled
- Updated `source` field to reflect decision source ("ml" or "ncd")

**Response Structure**:
```json
{
  "classification": "phish",
  "source": "ml",
  "ml_prediction": {
    "label": "phish",
    "probability": 0.85,
    "legit_probability": 0.15,
    "confidence": "high"
  },
  "ncd_scores": {...}
}
```

#### 5. Configuration (`src/config.py`)

**New Environment Variables**:
- `ML_ENABLED`: Enable/disable ML mode (default: `false`)
- `MODEL_PATH`: Path to trained model file (default: `models/model.pkl`)
- `MODEL_TYPE`: Type of classifier (default: `logistic_regression`)
- `ML_CONFIDENCE_THRESHOLD`: Minimum confidence to use ML result (default: `0.6`)

#### 6. Tests (`tests/test_model.py`)

**Coverage**:
- Model creation (Logistic Regression, Random Forest)
- Training on synthetic data
- Prediction functionality
- Save/load operations
- Error handling (untrained model, invalid model type)

**Run Tests**:
```bash
pytest tests/test_model.py -v
```

### File Structure

```
phishing-ncd-detector/
├── src/
│   ├── model.py              # ML model interface (NEW)
│   ├── detector.py           # Updated with ML integration
│   ├── api.py                # Updated with ML response
│   └── config.py             # Updated with ML config
├── tools/
│   └── train_model.py        # Training script (NEW)
├── tests/
│   └── test_model.py         # ML model tests (NEW)
├── models/                    # Directory for saved models (NEW)
│   └── model.pkl             # Trained model (generated)
└── requirements.txt          # Updated with scikit-learn
```

### Dependencies Added

- `scikit-learn==1.5.2`: Machine learning library

### Configuration Example

Add to `.env`:
```env
# Machine Learning Configuration
ML_ENABLED=true
MODEL_PATH=models/model.pkl
MODEL_TYPE=logistic_regression
ML_CONFIDENCE_THRESHOLD=0.6
```

### Workflow

1. **Training**:
   ```bash
   python tools/train_model.py
   ```

2. **Enable ML Mode**:
   - Set `ML_ENABLED=true` in `.env`
   - Restart server

3. **Detection**:
   - System extracts features from URL
   - ML model predicts classification
   - If ML confidence is high → use ML result
   - Otherwise → use NCD result
   - Return hybrid decision

### Hybrid Detection Strategy

The system uses a **confidence-based hybrid approach**:

1. **High ML Confidence** (≥ threshold):
   - Use ML prediction
   - Faster, more accurate for known patterns

2. **Low ML Confidence** (< threshold):
   - Fall back to NCD classification
   - More robust for novel/unknown patterns

3. **ML Unavailable**:
   - Use NCD-only mode
   - Graceful degradation

### Benefits

1. **Improved Accuracy**: ML models can learn complex patterns from data
2. **Hybrid Approach**: Combines strengths of both ML and NCD
3. **Flexibility**: Can switch between ML and NCD modes
4. **Extensibility**: Easy to add new model types
5. **Backward Compatible**: Works without ML enabled

### Future Enhancements

1. **Model Retraining**: Automatic retraining on new samples
2. **Ensemble Methods**: Combine multiple models
3. **Feature Engineering**: Add more sophisticated features
4. **Model Versioning**: Track model versions and performance
5. **A/B Testing**: Compare different models in production

### Testing

All tests pass:
```bash
pytest tests/test_model.py -v
# 11 tests passed
```

### Notes

- ML model requires at least 10 samples for training
- Model is loaded lazily (only when ML_ENABLED=true)
- Feature extraction must match FEATURE_ORDER (25 features)
- Model file is saved as pickle format (.pkl)

### Troubleshooting

**Issue**: "Model file not found"
- **Solution**: Train model first using `tools/train_model.py`

**Issue**: "Feature count mismatch"
- **Solution**: Ensure feature extraction returns all 25 features

**Issue**: "ML prediction failed"
- **Solution**: Check model file integrity, verify features format

**Issue**: "Low ML accuracy"
- **Solution**: Collect more training samples, tune hyperparameters


