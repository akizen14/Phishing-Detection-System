# src/api.py
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
from src.detector import load_dataset, classify_url

# Initialize FastAPI app with better metadata
app = FastAPI(
    title="🧠 AI-Driven Phishing Detector",
    description="""
🚀 **Phishing Detection Dashboard (HTML DOM-based)**  
This API analyzes a webpage's structure using **Normalized Compression Distance (NCD)**  
to determine if it's **legitimate or a phishing attempt**.

### How to Use:
1. Go to `/detect`
2. Enter a website URL (e.g., https://www.google.com)
3. Click **Execute**
4. View the similarity score and classification

---

💡 *Lower NCD → More similar to known legitimate pages.*  
If NCD > 0.25 (by default), the page is marked as **phish**.
""",
    version="2.0.0",
)

# Load dataset of reference samples
dataset = load_dataset()

@app.get("/", tags=["System Status"])
def home():
    """Check if the phishing detector API is live."""
    return {
        "status": "✅ Running",
        "message": "Welcome to the AI-Driven Phishing Detector API!",
        "docs": "Visit /docs to use the visual dashboard."
    }


@app.get("/detect", tags=["Phishing Detection"])
def detect(
    url: str = Query(
        ...,
        description="Enter the full website URL (with https://)",
        example="https://www.google.com"
    ),
    threshold: float = Query(
        0.25,
        description="NCD threshold for classifying phishing (lower = stricter)",
        example=0.25
    )
):
    """
    🔍 Analyze a webpage using its DOM structure similarity (NCD).

    **Steps:**
    1. The system fetches and renders the webpage.
    2. HTML DOM is cleaned and converted into a simplified representation.
    3. NCD is calculated against known samples.
    4. The site is classified as:
       - 🟢 Legitimate (if similar to trusted samples)
       - 🔴 Phish (if dissimilar)
    """
    result = classify_url(url, dataset, threshold)
    return JSONResponse(result)


@app.get("/samples", tags=["Dataset Overview"])
def list_samples():
    """List currently loaded reference samples."""
    if not dataset:
        return {"samples": 0, "message": "No samples loaded yet. Run test_extract.py first."}
    return {
        "samples": len(dataset),
        "examples": [s["meta"]["url"] for s in dataset[:5]]
    }
