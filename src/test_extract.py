import os
import time
import json
import hashlib
from src.extract_dom import extract_sanitized_dom

TEST_URLS = [
    "https://www.google.com",
    "https://example.com"
]


def save_sample(dom_bytes, url, label="legit", outdir="samples"):
    os.makedirs(outdir, exist_ok=True)
    ts = int(time.time())
    h = hashlib.md5(url.encode()).hexdigest()[:6]
    dom_path = os.path.join(outdir, f"{ts}_{h}.dom")
    meta_path = dom_path.replace(".dom", ".meta.json")
    with open(dom_path, "wb") as f:
        f.write(dom_bytes)
    with open(meta_path, "w") as f:
        json.dump({"url": url, "label": label}, f)
    print(f"Saved sample: {dom_path}")


def main():
    for url in TEST_URLS:
        print(f"Rendering: {url}")
        dom = extract_sanitized_dom(url)
        if dom:
            save_sample(dom, url)
        else:
            print(f"[ERROR] failed for {url}")


if __name__ == "__main__":
    main()
