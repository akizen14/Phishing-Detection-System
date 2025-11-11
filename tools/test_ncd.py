"""
Simple NCD test script
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.extract_dom import extract_sanitized_dom

url = input("Enter URL: ").strip()
dom = extract_sanitized_dom(url)
