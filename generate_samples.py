# scripts/generate_samples.py
import os
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.extract_dom import extract_sanitized_dom
from src.save import save_dom_bytes

OUTDIR = Path("samples")
OUTDIR.mkdir(exist_ok=True)

def process_url(url, label, mode="tags_only", headless=True, wait_seconds=2):
    dom = extract_sanitized_dom(url, mode=mode, wait_seconds=wait_seconds, headless=headless)
    if dom:
        base, dom_path, meta_path = save_dom_bytes(url, dom, out_dir=str(OUTDIR))
        # ensure label in meta
        try:
            import json
            m = {}
            with open(meta_path, "r", encoding="utf-8") as f:
                m = json.load(f)
            m["label"] = label
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(m, f, indent=2)
        except Exception as e:
            print("meta write error:", e)
        return True, url
    else:
        return False, url

def load_urls(path):
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

def main():
    phish_urls = load_urls("urls-phish.txt")
    legit_urls = load_urls("urls-legit.txt")

    tasks = []
    # parallel to speed up rendering (adjust max_workers carefully)
    with ThreadPoolExecutor(max_workers=3) as ex:
        for u in phish_urls:
            tasks.append(ex.submit(process_url, u, "phish"))
        for u in legit_urls:
            tasks.append(ex.submit(process_url, u, "legit"))
        for fut in as_completed(tasks):
            ok, url = fut.result()
            print(("OK" if ok else "FAIL"), url)

if __name__ == "__main__":
    main()
