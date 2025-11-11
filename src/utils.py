"""
Utility functions for the phishing detection system.
"""
from pathlib import Path
from typing import List


def load_urls_from_file(filepath: Path) -> List[str]:
    """
    Load URLs from a text file, ignoring comments and empty lines.
    
    Args:
        filepath: Path to the URL list file
        
    Returns:
        List of URLs
    """
    if not filepath.exists():
        print(f"[WARNING] URL file not found: {filepath}")
        return []
    
    with open(filepath, "r", encoding="utf-8") as f:
        urls = [
            line.strip() 
            for line in f 
            if line.strip() and not line.startswith("#")
        ]
    
    return urls


def ensure_dir(path: Path) -> None:
    """
    Ensure a directory exists, creating it if necessary.
    
    Args:
        path: Directory path to ensure exists
    """
    path.mkdir(parents=True, exist_ok=True)
