"""
Build a manifest JSON file from all samples in the samples/ directory.
"""
import os
import glob
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = ROOT / "samples"
OUTPUT_FILE = ROOT / "dataset_manifest.json"


def build_manifest():
    """Build manifest from all .dom files in samples directory."""
    samples = []
    
    for dom_file in sorted(SAMPLES_DIR.glob("*.dom")):
        meta_file = dom_file.with_suffix(".meta.json")
        
        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            label = meta.get("label", "unknown")
        except Exception as e:
            print(f"[WARNING] Could not load metadata for {dom_file.name}: {e}")
            label = "unknown"
            meta = {}
        
        samples.append({
            "dom": str(dom_file.relative_to(ROOT)),
            "meta": str(meta_file.relative_to(ROOT)),
            "label": label
        })
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(samples, f, indent=2)
    
    print(f"✓ Manifest written: {len(samples)} samples")
    print(f"  Output: {OUTPUT_FILE}")


if __name__ == "__main__":
    build_manifest()
