"""
FastAPI application for phishing detection service.
"""
import os
import logging
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from src.detector import load_dataset, classify_url, classify_dom_ncd
from src.extract_dom import extract_sanitized_dom
from src.config import WEB_DIR, DEFAULT_NCD_THRESHOLD
from src.phishtank_client import phishtank_lookup, get_metrics as get_phishtank_metrics

logger = logging.getLogger("api")

app = FastAPI(
    title="AI-Driven Phishing Detector",
    description="NCD-based DOM similarity phishing detector (local demo)",
    version="2.0.0",
)

# Mount static web folder
if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


# Load dataset once at startup
dataset = load_dataset()


@app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
def index():
    index_file = WEB_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return HTMLResponse("<h3>Dashboard not found. Ensure /web/index.html exists</h3>")


@app.get("/detect", tags=["Phishing Detection"])
def detect(
    url: str = Query(..., description="Full URL to analyze (include scheme)"),
    skip_ncd: bool = Query(False, description="Skip NCD analysis (signature only)")
):
    """
    Analyze the URL using hybrid detection: signature + NCD.
    
    Detection flow:
    1. Check PhishTank signature database (fast, high-confidence)
    2. If verified phishing → return immediately as PHISHING
    3. If not found → perform NCD structural analysis
    
    Args:
        url: Full URL to analyze (must include http:// or https://)
        skip_ncd: Skip NCD analysis and only use signature lookup
        
    Returns:
        JSON with classification results including source and confidence
    """
    # Step 1: PhishTank signature lookup
    sig_result = phishtank_lookup(url, skip_signature=False)
    
    # Check if verified phishing URL
    if sig_result.get("in_database") and sig_result.get("verified"):
        logger.info(f"PhishTank HIT: {url} (phish_id: {sig_result['phish_id']})")
        return JSONResponse({
            "url": url,
            "classification": "phish",
            "source": "signature-local",
            "confidence": "high",
            "phish_id": sig_result["phish_id"],
            "detail_page": sig_result["detail_page"],
            "submitted_at": sig_result["submitted_at"]
        })
    
    # Step 2: Not in signature database - perform NCD analysis
    if skip_ncd:
        logger.info(f"PhishTank SAFE (NCD skipped): {url}")
        return JSONResponse({
            "url": url,
            "classification": "legit",
            "source": "signature-local",
            "confidence": "medium",
            "message": "URL not found in PhishTank database, NCD analysis skipped"
        })
    
    logger.info(f"PhishTank miss, performing NCD analysis: {url}")
    
    # Extract DOM
    dom = extract_sanitized_dom(url)
    if not dom:
        logger.error(f"Failed to extract DOM for {url}")
        return JSONResponse({
            "url": url,
            "classification": "unknown",
            "source": "error",
            "confidence": "low",
            "error": "Unable to extract DOM from URL"
        })
    
    # Perform NCD classification
    ncd_result = classify_dom_ncd(dom)
    
    return JSONResponse({
        "url": url,
        "classification": ncd_result["verdict"],
        "source": "ncd",
        "confidence": "medium" if ncd_result["verdict"] == "phish" else "low",
        "ncd_score_phish": ncd_result["ncd_score_phish_best"],
        "ncd_score_legit": ncd_result["ncd_score_legit_best"]
    })


@app.get("/samples", tags=["Dataset Overview"])
def samples():
    """
    Get dataset statistics and sample URLs.
    
    Returns:
        JSON with total sample count and example URLs
    """
    if not dataset:
        return {"samples": 0, "examples": [], "labels": {}}
    
    # Count labels
    label_counts = {}
    for sample in dataset:
        label = sample.get("label", "unknown")
        label_counts[label] = label_counts.get(label, 0) + 1
    
    # Return statistics
    return {
        "samples": len(dataset),
        "labels": label_counts,
        "examples": [s["meta"].get("url", "-") for s in dataset[:10]]
    }


@app.get("/metrics", tags=["Monitoring"])
def metrics():
    """
    Get system metrics including PhishTank statistics.
    
    Returns:
        JSON with detection metrics
    """
    phishtank_metrics = get_phishtank_metrics()
    
    return {
        "phishtank": phishtank_metrics,
        "ncd": {
            "samples_loaded": len(dataset)
        }
    }
