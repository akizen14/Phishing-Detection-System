"""
Validate samples directory to ensure all .dom files have corresponding metadata.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = ROOT / "samples"


def validate_samples():
    """Validate all samples have proper metadata and labels."""
    dom_files = list(SAMPLES_DIR.glob("*.dom"))
    print(f"Found {len(dom_files)} DOM files")
    
    missing_meta = []
    missing_label = []
    invalid_json = []
    
    for dom_file in dom_files:
        meta_file = dom_file.with_suffix(".meta.json")
        
        # Check if metadata file exists
        if not meta_file.exists():
            missing_meta.append(dom_file.name)
            continue
        
        # Try to load and validate metadata
        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            
            # Check for required fields
            if "label" not in meta:
                missing_label.append(meta_file.name)
            if "url" not in meta:
                print(f"[WARNING] {meta_file.name} missing 'url' field")
            
        except json.JSONDecodeError as e:
            invalid_json.append((meta_file.name, str(e)))
        except Exception as e:
            print(f"[ERROR] {meta_file.name}: {e}")
    
    # Print results
    print(f"\n{'='*60}")
    print("VALIDATION RESULTS")
    print(f"{'='*60}")
    print(f"Total DOM files: {len(dom_files)}")
    print(f"Missing metadata files: {len(missing_meta)}")
    print(f"Missing labels: {len(missing_label)}")
    print(f"Invalid JSON: {len(invalid_json)}")
    
    if missing_meta:
        print(f"\nMissing metadata (showing first 5):")
        for name in missing_meta[:5]:
            print(f"  - {name}")
    
    if missing_label:
        print(f"\nMissing labels (showing first 5):")
        for name in missing_label[:5]:
            print(f"  - {name}")
    
    if invalid_json:
        print(f"\nInvalid JSON:")
        for name, error in invalid_json:
            print(f"  - {name}: {error}")
    
    # Summary
    if not (missing_meta or missing_label or invalid_json):
        print("\n✓ All samples are valid!")
    else:
        print("\n✗ Validation issues found")
    
    print(f"{'='*60}")


if __name__ == "__main__":
    validate_samples()
