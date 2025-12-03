"""
FastAPI application for phishing detection service.
"""
import os
import json
import uuid
import logging
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from src.detector import load_dataset, classify_url, classify_url_ncd
from src.config import WEB_DIR, DEFAULT_NCD_THRESHOLD, ROOT_DIR
from src.phishtank_client import phishtank_lookup, get_metrics as get_phishtank_metrics
from src.domain_info import get_domain_info
from src.cert_info import get_certificate_metadata
from src.reverse_dns import get_hosting_info

logger = logging.getLogger("api")

# Feedback log file
FEEDBACK_LOG_FILE = ROOT_DIR / "feedback_log.json"

# In-memory detection cache for feedback (detection_id -> detection_data)
detection_cache = {}

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


@app.get("/test.html", response_class=HTMLResponse, tags=["Dashboard"])
def test_page():
    test_file = WEB_DIR / "test.html"
    if test_file.exists():
        return FileResponse(test_file)
    return HTMLResponse("<h3>Test page not found</h3>")


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
    
    # Perform NCD classification (with automatic resource signature fallback)
    ncd_result = classify_url_ncd(url)
    
    # Check for errors
    if ncd_result.get("error"):
        return JSONResponse({
            "url": url,
            "classification": "unknown",
            "source": "error",
            "confidence": "low",
            "error": ncd_result["error"]
        })
    
    # Generate unique detection ID for feedback
    detection_id = str(uuid.uuid4())
    
    # Use final verdict if available (from hybrid ML+NCD decision), otherwise use NCD verdict
    final_classification = ncd_result.get("final_verdict", ncd_result["verdict"])
    decision_source = ncd_result.get("decision_source", "ncd")
    
    # Build response with prototype scores (preferred) or NCD scores (backward compatibility)
    if "prototype_scores" in ncd_result:
        # New prototype-based response
        prototype_scores = ncd_result["prototype_scores"]
        response_data = {
            "url": url,
            "classification": final_classification,
            "source": decision_source,  # "ml", "prototype", or "ncd"
            "confidence": ncd_result.get("confidence", "medium" if "phish" in final_classification else "low"),
            "prototype_scores": {
                "phish_min": prototype_scores["phish_min"],
                "phish_avg": prototype_scores["phish_avg"],
                "legit_min": prototype_scores["legit_min"],
                "legit_avg": prototype_scores["legit_avg"]
            },
            "final_decision": ncd_result.get("final_decision", ""),
            "dom_size": ncd_result.get("dom_size", 0),
            "minimal_dom_adjustment_applied": ncd_result.get("minimal_dom_adjustment_applied", False),
            "features": ncd_result.get("features", {})
        }
        # Backward compatibility: also include ncd_scores
        response_data["ncd_scores"] = {
            "phish_best": prototype_scores["phish_min"],
            "phish_avg": prototype_scores["phish_avg"],
            "legit_best": prototype_scores["legit_min"],
            "legit_avg": prototype_scores["legit_avg"]
        }
    else:
        # Legacy NCD-based response
        response_data = {
            "url": url,
            "classification": final_classification,
            "source": decision_source,  # "ml", "ncd", or "ncd-clustered"
            "confidence": "medium" if "phish" in final_classification else "low",
            "ncd_scores": {
                "phish_best": ncd_result["ncd_score_phish_best"],
                "phish_avg": ncd_result.get("ncd_score_phish_avg", ncd_result["ncd_score_phish_best"]),
                "legit_best": ncd_result["ncd_score_legit_best"],
                "legit_avg": ncd_result.get("ncd_score_legit_avg", ncd_result["ncd_score_legit_best"])
            },
            "features": ncd_result.get("features", {})
        }
    
    # Add ML prediction if available
    if "ml_prediction" in ncd_result:
        ml_pred = ncd_result["ml_prediction"]
        response_data["ml_prediction"] = {
            "label": ml_pred.get("label", "legit"),
            "probability": ml_pred.get("probability", 0.0),
            "legit_probability": ml_pred.get("legit_probability", 1.0),
            "confidence": ml_pred.get("confidence", "low")
        }
    
    # Keep backward compatibility
    response_data["ncd_score_phish"] = ncd_result["ncd_score_phish_best"]
    response_data["ncd_score_legit"] = ncd_result["ncd_score_legit_best"]
    
    # Cluster information is used internally but not exposed to users
    
    # Add detection mode information
    if "detection_mode" in ncd_result:
        response_data["detection_mode"] = ncd_result["detection_mode"]
        response_data["dom_length"] = ncd_result["dom_length"]
        if "resource_sig_length" in ncd_result:
            response_data["resource_sig_length"] = ncd_result["resource_sig_length"]
    
    # Add explanation if available
    if "reason" in ncd_result:
        response_data["reason"] = ncd_result["reason"]
    
    # Add feedback URL
    response_data["feedback_url"] = f"/feedback?id={detection_id}"
    response_data["detection_id"] = detection_id
    
    # Collect OSINT metadata (in parallel for speed)
    logger.info(f"Collecting OSINT metadata for {url}")
    
    # Get IP and reverse DNS
    ip, reverse_dns_hostname = get_hosting_info(url)
    if ip:
        response_data["ip"] = ip
        response_data["hosting_reverse_dns"] = reverse_dns_hostname
    
    # Get domain information
    domain_info = get_domain_info(url)
    response_data["registrar"] = domain_info["registrar"]
    response_data["domain_age_days"] = domain_info["domain_age_days"]
    response_data["domain_created"] = domain_info["created"]
    response_data["domain_expires"] = domain_info["expires"]
    response_data["nameservers"] = domain_info["nameservers"]
    response_data["mx_records"] = domain_info["mx_records"]
    
    # Get SSL certificate information
    cert_info = get_certificate_metadata(url)
    response_data["ssl_enabled"] = cert_info["ssl_enabled"]
    response_data["ssl_issuer"] = cert_info["ssl_issuer"]
    response_data["ssl_valid_from"] = cert_info["ssl_valid_from"]
    response_data["ssl_valid_to"] = cert_info["ssl_valid_to"]
    
    # Cache detection data for feedback
    detection_cache[detection_id] = {
        "url": url,
        "verdict": ncd_result["verdict"],
        "timestamp": datetime.now().isoformat(),
        "response": response_data
    }
    
    return JSONResponse(response_data)


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


@app.get("/feedback", tags=["User Feedback"])
def feedback(
    id: str = Query(..., description="Detection ID from the detection response"),
    correct: str = Query(..., description="Was the classification correct? (yes/no)")
):
    """
    Submit user feedback on a detection result.
    
    This helps improve the system by collecting real-world validation data.
    
    Args:
        id: Unique detection ID from the /detect response
        correct: Whether the classification was correct ("yes" or "no")
        
    Returns:
        JSON confirmation of feedback submission
    """
    # Validate correct parameter
    if correct.lower() not in ["yes", "no"]:
        return JSONResponse({
            "error": "Invalid 'correct' parameter. Must be 'yes' or 'no'."
        }, status_code=400)
    
    # Check if detection ID exists in cache
    if id not in detection_cache:
        return JSONResponse({
            "error": "Detection ID not found. It may have expired or be invalid."
        }, status_code=404)
    
    # Get detection data
    detection_data = detection_cache[id]
    
    # Create feedback entry
    feedback_entry = {
        "id": id,
        "url": detection_data["url"],
        "verdict": detection_data["verdict"],
        "user_feedback": correct.lower(),
        "timestamp": datetime.now().isoformat(),
        "detection_timestamp": detection_data["timestamp"]
    }
    
    # Append to feedback log file
    try:
        # Load existing feedback or create new list
        if FEEDBACK_LOG_FILE.exists():
            with open(FEEDBACK_LOG_FILE, "r", encoding="utf-8") as f:
                feedback_log = json.load(f)
        else:
            feedback_log = []
        
        # Append new feedback
        feedback_log.append(feedback_entry)
        
        # Save back to file
        with open(FEEDBACK_LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(feedback_log, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Feedback recorded: {id} - {correct}")
        
        return JSONResponse({
            "status": "success",
            "message": "Thank you for your feedback!",
            "feedback": feedback_entry
        })
        
    except Exception as e:
        logger.error(f"Failed to save feedback: {e}")
        return JSONResponse({
            "error": "Failed to save feedback. Please try again."
        }, status_code=500)


@app.get("/metrics", tags=["Monitoring"])
def metrics():
    """
    Get system metrics including PhishTank statistics.
    
    Returns:
        JSON with detection metrics
    """
    phishtank_metrics = get_phishtank_metrics()
    
    # Count feedback entries
    feedback_count = 0
    if FEEDBACK_LOG_FILE.exists():
        try:
            with open(FEEDBACK_LOG_FILE, "r", encoding="utf-8") as f:
                feedback_log = json.load(f)
                feedback_count = len(feedback_log)
        except:
            pass
    
    return {
        "phishtank": phishtank_metrics,
        "ncd": {
            "samples_loaded": len(dataset)
        },
        "feedback": {
            "total_submissions": feedback_count
        }
    }
