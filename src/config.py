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
DEFAULT_NCD_THRESHOLD = float(os.getenv("DEFAULT_NCD_THRESHOLD", "0.25"))
DEFAULT_WAIT_SECONDS = int(os.getenv("DEFAULT_WAIT_SECONDS", "2"))
DEFAULT_HEADLESS = os.getenv("DEFAULT_HEADLESS", "true").lower() == "true"

# Sanitization modes
SANITIZE_MODE_TAGS_ONLY = "tags_only"
SANITIZE_MODE_TAGS_ATTRS = "tags_attrs"
