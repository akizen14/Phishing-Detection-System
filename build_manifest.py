# scripts/build_manifest.py
import os, glob, json

samples = []
for dom in sorted(glob.glob("samples/*.dom")):
    meta_file = dom.replace(".dom", ".meta.json")
    try:
        meta = json.load(open(meta_file, encoding="utf-8"))
        label = meta.get("label", "unknown")
    except Exception:
        label = "unknown"
    samples.append({"dom": dom, "meta": meta_file, "label": label})

with open("dataset_manifest.json", "w", encoding="utf-8") as f:
    json.dump(samples, f, indent=2)
print("manifest written:", len(samples))
