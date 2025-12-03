"""
Configuration management for the phishing detection system.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Project paths
ROOT_DIR = Path(__file__).resolve().parent.parent
SAMPLES_DIR = ROOT_DIR / os.getenv("SAMPLES_DIR", "samples")
WEB_DIR = ROOT_DIR / "web"

# Chrome Driver
CHROMEDRIVER_PATH = os.getenv("CHROMEDRIVER_PATH")

# API Configuration
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))

# Detection Parameters
DEFAULT_NCD_THRESHOLD = float(os.getenv("DEFAULT_NCD_THRESHOLD", "0.48"))
DEFAULT_WAIT_SECONDS = int(os.getenv("DEFAULT_WAIT_SECONDS", "2"))
DEFAULT_HEADLESS = os.getenv("DEFAULT_HEADLESS", "true").lower() == "true"

# NCD Classification Parameters (tunable)
NCD_MIN_SEPARATION_MARGIN = float(os.getenv("NCD_MIN_SEPARATION_MARGIN", "0.02"))  # Minimum difference for confident classification
NCD_CLOSE_MARGIN = float(os.getenv("NCD_CLOSE_MARGIN", "0.05"))  # If scores within this, classify as phish (conservative)
NCD_ABSOLUTE_THRESHOLD = float(os.getenv("NCD_ABSOLUTE_THRESHOLD", "0.65"))  # High score threshold
NCD_CONSERVATIVE_BIAS = os.getenv("NCD_CONSERVATIVE_BIAS", "true").lower() == "true"  # Prefer false positives

# Sanitization modes
SANITIZE_MODE_TAGS_ONLY = "tags_only"
SANITIZE_MODE_TAGS_ATTRS = "tags_attrs"

# Machine Learning Configuration
ML_ENABLED = os.getenv("ML_ENABLED", "false").lower() == "true"
MODEL_PATH = os.getenv("MODEL_PATH", str(ROOT_DIR / "models" / "model.pkl"))
MODEL_TYPE = os.getenv("MODEL_TYPE", "logistic_regression")  # logistic_regression or random_forest
ML_CONFIDENCE_THRESHOLD = float(os.getenv("ML_CONFIDENCE_THRESHOLD", "0.6"))  # Use NCD if ML confidence below this

# Minimal DOM Configuration
MINIMAL_DOM_THRESHOLD = int(os.getenv("MINIMAL_DOM_THRESHOLD", "300"))  # Bytes - DOMs smaller than this are considered minimal
MINIMAL_DOM_PENALTY = float(os.getenv("MINIMAL_DOM_PENALTY", "0.05"))  # Penalty added to legit scores for minimal DOMs
