"""
Main entry point for the phishing detection API server.
"""
import uvicorn
from src.config import API_HOST, API_PORT


if __name__ == "__main__":
    print(f"Starting Phishing Detection API on {API_HOST}:{API_PORT}")
    print(f"Dashboard: http://{API_HOST}:{API_PORT}/")
    print(f"API Docs: http://{API_HOST}:{API_PORT}/docs")
    
    uvicorn.run(
        "src.api:app",
        host=API_HOST,
        port=API_PORT,
        reload=True,
        log_level="info"
    )
