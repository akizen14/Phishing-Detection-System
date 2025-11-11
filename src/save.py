"""
Helpers to save DOM bytes and metadata JSON into samples/ folder.
"""
import json
import time
import hashlib
from pathlib import Path
from typing import Tuple


def save_dom_bytes(url: str, dom_bytes: bytes, out_dir: str = "samples") -> Tuple[str, str, str]:
    """
    Save DOM bytes and metadata to disk.
    
    Creates two files:
      - <out_dir>/<timestamp>_<hash>.dom (binary DOM data)
      - <out_dir>/<timestamp>_<hash>.meta.json (metadata)
    
    Args:
        url: Source URL
        dom_bytes: Sanitized DOM bytes
        out_dir: Output directory path
        
    Returns:
        Tuple of (base_filename, dom_path, meta_path)
    """
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    
    # Generate unique filename
    h = hashlib.sha1(url.encode("utf-8") + str(time.time()).encode("utf-8")).hexdigest()[:12]
    ts = int(time.time())
    base = f"{ts}_{h}"
    
    dom_path = out_path / f"{base}.dom"
    meta_path = out_path / f"{base}.meta.json"

    # Write DOM bytes
    with open(dom_path, "wb") as f:
        f.write(dom_bytes)

    # Write metadata
    meta = {
        "url": url,
        "ts": ts,
        "size": len(dom_bytes)
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    
    return base, str(dom_path), str(meta_path)
