import os
import lzma
import json
import hashlib
from src.extract_dom import extract_sanitized_dom


def compress_size(data: bytes) -> int:
    return len(lzma.compress(data))


def ncd(x: bytes, y: bytes) -> float:
    """
    Normalized Compression Distance (NCD)
    """
    c_x = compress_size(x)
    c_y = compress_size(y)
    c_xy = compress_size(x + y)
    return (c_xy - min(c_x, c_y)) / max(c_x, c_y)


def classify_url(url: str, dataset, threshold: float = 0.25):
    """
    Compare a new URL’s DOM with samples to detect phishing.
    """
    dom = extract_sanitized_dom(url)
    if not dom:
        return {"url": url, "error": "Unable to fetch DOM"}

    min_distance = 1.0
    label = "unknown"

    for sample in dataset:
        dist = ncd(dom, sample["dom"])
        if dist < min_distance:
            min_distance = dist
            label = sample["label"]

    if min_distance > threshold:
        label = "phish"

    return {"url": url, "ncd": min_distance, "classification": label}


def load_dataset(samples_dir="samples"):
    dataset = []
    for filename in os.listdir(samples_dir):
        if filename.endswith(".dom"):
            meta_file = filename.replace(".dom", ".meta.json")
            dom_path = os.path.join(samples_dir, filename)
            meta_path = os.path.join(samples_dir, meta_file)
            try:
                with open(dom_path, "rb") as f1, open(meta_path, "r") as f2:
                    dataset.append({
                        "dom": f1.read(),
                        "meta": json.load(f2),
                        "label": json.load(f2).get("label", "legit")
                    })
            except Exception as e:
                print(f"[ERROR] loading sample {filename}: {e}")
    return dataset
