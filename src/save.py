# save.py
# Helpers to save .dom bytes and metadata JSON into samples/ folder.

import os
import json
import time
import hashlib


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def save_dom_bytes(url: str, dom_bytes: bytes, out_dir: str = "samples"):
    """
    Saves:
      <out_dir>/<timestamp>_<hash>.dom
      <out_dir>/<timestamp>_<hash>.meta.json
    Returns the base filename (without extension).
    """
    ensure_dir(out_dir)
    h = hashlib.sha1(url.encode("utf-8") + str(time.time()).encode("utf-8")).hexdigest()[:12]
    ts = int(time.time())
    base = f"{ts}_{h}"
    dom_path = os.path.join(out_dir, base + ".dom")
    meta_path = os.path.join(out_dir, base + ".meta.json")

    with open(dom_path, "wb") as f:
        f.write(dom_bytes)

    meta = {
        "url": url,
        "ts": ts,
        "size": len(dom_bytes)
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    return base, dom_path, meta_path
