# AI-Driven Phishing Detection System - Comprehensive Guide

**Version**: 2.0.0 | **Status**: Production Ready | **Last Updated**: December 4, 2025

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Project Architecture](#project-architecture)
3. [Complete Project Structure](#complete-project-structure)
4. [Technology Stack](#technology-stack)
5. [Detection Pipeline](#detection-pipeline)
6. [API Endpoints](#api-endpoints)
7. [Configuration Guide](#configuration-guide)
8. [Database Details](#database-details)
9. [Installation & Setup](#installation--setup)
10. [Usage Examples](#usage-examples)
11. [Performance Metrics](#performance-metrics)
12. [Security Features](#security-features)
13. [Dashboard Features](#dashboard-features)
14. [Development Workflow](#development-workflow)
15. [Testing](#testing)
16. [Troubleshooting](#troubleshooting)
17. [Future Enhancements](#future-enhancements)

---

## Executive Summary

The **AI-Driven Phishing Detection System** is an advanced security platform that identifies phishing websites using a hybrid detection approach combining:

1. **Signature-based Detection** - Fast matching against PhishTank's verified phishing database (48K+ URLs)
2. **Structural Analysis** - Deep DOM structure comparison using Normalized Compression Distance (NCD) algorithm
3. **OSINT Intelligence** - Domain, SSL, hosting, and DNS information gathering

### Key Capabilities

- ✅ **Hybrid Detection**: Two-phase approach (signature + structural analysis)
- ✅ **Fast Signature Matching**: < 1ms local database lookups
- ✅ **DOM Sanitization**: Extracts structural features while removing content
- ✅ **REST API**: FastAPI-powered detection service with auto-documentation
- ✅ **Local Database**: Offline-capable SQLite PhishTank database
- ✅ **Intelligent Caching**: TTL-based caching (1-hour default)
- ✅ **Professional Dashboard**: White-blue themed web interface
- ✅ **Batch Processing**: Parallel URL processing
- ✅ **OSINT Intelligence**: Domain, SSL, DNS, hosting information
- ✅ **User Feedback System**: Collects classification accuracy data
- ✅ **Comprehensive Testing**: Full test suite with pytest

---

## Project Architecture

### System Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    User Request (URL)                        │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │   FastAPI Server      │
              │   (src/api.py)        │
              └──────────┬───────────┘
                         │
                         ▼
         ┌────────────────────────────────┐
         │   Phase 1: Signature Lookup    │
         │   (PhishTank Database)         │
         └──────────┬─────────────────────┘
                    │
         ┌──────────┴──────────┐
         │ Found?               │ Not Found
         ▼                      ▼
    ┌─────────┐         ┌──────────────────┐
    │ Return  │         │ Phase 2: NCD     │
    │ Result  │         │ Analysis         │
    └─────────┘         └────────┬─────────┘
                                 │
                    ┌────────────┴────────────┐
                    │                          │
            ┌───────▼───────┐        ┌────────▼────────┐
            │ DOM Structure │        │ Resource        │
            │ Analysis      │        │ Signature       │
            └───────┬───────┘        └────────┬────────┘
                    │                        │
                    └────────────┬───────────┘
                                 │
                         ┌───────▼────────┐
                         │ Classification │
                         │ & OSINT Data   │
                         └───────┬────────┘
                                 │
                         ┌───────▼────────┐
                         │ Return Result  │
                         └────────────────┘
```

### Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Presentation Layer                     │
├─────────────────────────────────────────────────────────────┤
│  Web Dashboard (web/index.html)                              │
│  - Professional white-blue theme                             │
│  - Real-time detection interface                            │
│  - Metrics and statistics display                           │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                      API Layer                                │
├─────────────────────────────────────────────────────────────┤
│  FastAPI Application (src/api.py)                            │
│  - /detect - Main detection endpoint                         │
│  - /metrics - System metrics                                 │
│  - /samples - Dataset statistics                            │
│  - /feedback - User feedback collection                     │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                    Detection Engine                           │
├─────────────────────────────────────────────────────────────┤
│  Hybrid Detection (src/detector.py)                          │
│  ├─ PhishTank Client (src/phishtank_client.py)              │
│  │  └─ Local SQLite DB (src/db_phishtank.sqlite)            │
│  └─ NCD Classifier (src/detector.py)                         │
│     ├─ DOM Extraction (src/extract_dom.py)                  │
│     │  ├─ Render (src/render.py) - Selenium                  │
│     │  └─ Sanitize (src/sanitize.py) - BeautifulSoup        │
│     └─ NCD Computation (src/ncd.py) - LZMA compression      │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                    Intelligence Layer                          │
├─────────────────────────────────────────────────────────────┤
│  OSINT Modules                                                │
│  ├─ Domain Info (src/domain_info.py) - WHOIS                │
│  ├─ SSL Certificate (src/cert_info.py) - TLS analysis       │
│  └─ Reverse DNS (src/reverse_dns.py) - Hosting info         │
└──────────────────────────────────────────────────────────────┘
```

---

## Complete Project Structure

```
phishing-ncd-detector/
│
├── src/                                    # Core Application Code
│   ├── __init__.py                        # Package initialization
│   ├── api.py                             # FastAPI REST API endpoints (13 KB)
│   ├── config.py                          # Configuration management (2 KB)
│   ├── detector.py                        # Main detection logic & NCD classification (16 KB)
│   ├── extract_dom.py                     # DOM extraction pipeline (1 KB)
│   ├── render.py                          # Selenium web rendering (2 KB)
│   ├── sanitize.py                        # HTML sanitization (1 KB)
│   ├── ncd.py                             # NCD computation with LZMA (1 KB)
│   ├── phishtank_client.py                # PhishTank database client (4 KB)
│   ├── prototypes.py                      # Base phishing/legit prototypes (13 KB)
│   ├── prototypes_clustered.py            # Clustered phishing prototypes (2 KB)
│   ├── resource_graph.py                  # Resource signature extraction (5 KB)
│   ├── domain_info.py                     # Domain/WHOIS information (4 KB)
│   ├── cert_info.py                       # SSL certificate analysis (4 KB)
│   ├── reverse_dns.py                     # Reverse DNS & hosting info (2 KB)
│   ├── features.py                        # Feature extraction for ML (13 KB)
│   ├── model.py                           # ML model integration (8 KB)
│   ├── save.py                            # Sample persistence (1 KB)
│   ├── utils.py                           # Utility functions (1 KB)
│   └── db_phishtank.sqlite                # Local PhishTank database (23 MB, 48K+ entries)
│
├── tools/                                  # Utility Tools
│   ├── __init__.py                        # Package initialization
│   ├── phishtank_update_local.py          # PhishTank CSV updater (8 KB) ⭐ PRIMARY
│   ├── phishtank_update.py                # PhishTank JSON updater (7 KB)
│   ├── cluster_phish_prototypes.py        # Prototype clustering (9 KB)
│   ├── collect_legit_samples.py           # Collect legitimate samples (5 KB)
│   ├── train_model.py                     # ML model training (9 KB)
│   ├── tune_threshold.py                  # NCD threshold tuning (4 KB)
│   └── test_ncd.py                        # NCD testing utilities (264 B)
│
├── scripts/                                # Automation Scripts
│   ├── __init__.py                        # Package initialization
│   ├── generate_samples.py                # Generate DOM samples from URLs
│   ├── build_manifest.py                  # Build dataset manifest
│   └── validate_samples.py                # Validate sample integrity
│
├── tests/                                  # Test Suite
│   ├── __init__.py                        # Test package initialization
│   ├── conftest.py                        # Pytest fixtures and configuration
│   ├── test_api_integration.py            # API integration tests
│   ├── test_detector.py                   # Detector logic tests
│   ├── test_ncd.py                        # NCD computation tests
│   ├── test_phishtank_client.py           # PhishTank client tests
│   ├── test_sanitize.py                   # Sanitization tests
│   └── test_utils.py                      # Utility function tests
│
├── samples/                                # DOM Samples Database
│   ├── *.dom                              # Binary DOM files
│   ├── *.meta.json                        # Metadata files
│   ├── legit/                             # Legitimate website samples
│   ├── phishing/                          # Phishing website samples
│   └── phishing_clustered/                # Clustered phishing samples
│       ├── cluster_1/
│       ├── cluster_2/
│       └── cluster_3/
│
├── web/                                    # Web Dashboard
│   └── index.html                         # Professional white-blue themed UI
│
├── main.py                                 # Application entry point
├── requirements.txt                        # Python dependencies (30 packages)
├── .env                                    # Environment configuration
├── .env.example                            # Environment template
├── .gitignore                              # Git ignore rules
├── pytest.ini                              # Pytest configuration
├── dataset_manifest.json                   # Dataset manifest
├── urls-phish.txt                          # Phishing URL list
├── urls-legit.txt                          # Legitimate URL list
├── README.md                               # Main documentation
├── PROJECT_OVERVIEW.md                     # Detailed overview
├── STRUCTURE.md                            # Architecture documentation
├── PHISHTANK_INTEGRATION.md                # PhishTank setup guide
└── COMPREHENSIVE_GUIDE.md                  # This file
```

### Module Responsibilities

#### Core Modules (`src/`)

| Module | Size | Purpose |
|--------|------|---------|
| `api.py` | 13 KB | FastAPI REST API endpoints, request/response handling |
| `detector.py` | 16 KB | Main detection logic, NCD classification, prototype matching |
| `phishtank_client.py` | 4 KB | PhishTank database client with caching and metrics |
| `ncd.py` | 1 KB | NCD computation using LZMA compression |
| `extract_dom.py` | 1 KB | DOM extraction pipeline orchestration |
| `render.py` | 2 KB | Selenium WebDriver setup and page rendering |
| `sanitize.py` | 1 KB | HTML sanitization (tags-only or tags+attributes) |
| `config.py` | 2 KB | Configuration management from environment variables |
| `prototypes.py` | 13 KB | Base phishing and legitimate prototypes |
| `prototypes_clustered.py` | 2 KB | Clustered phishing prototypes (3 clusters) |
| `resource_graph.py` | 5 KB | Resource signature extraction for dynamic content |
| `domain_info.py` | 4 KB | WHOIS domain information gathering |
| `cert_info.py` | 4 KB | SSL/TLS certificate analysis |
| `reverse_dns.py` | 2 KB | Reverse DNS and hosting provider lookup |
| `features.py` | 13 KB | Feature extraction for ML models |
| `model.py` | 8 KB | ML model integration (logistic regression, random forest) |
| `save.py` | 1 KB | DOM sample persistence utilities |
| `utils.py` | 1 KB | Common utility functions |

#### Tools (`tools/`)

| Tool | Size | Purpose |
|------|------|---------|
| `phishtank_update_local.py` | 8 KB | ⭐ PRIMARY: Download PhishTank CSV, build SQLite database |
| `phishtank_update.py` | 7 KB | Alternative JSON-based updater |
| `cluster_phish_prototypes.py` | 9 KB | Clustering algorithm for phishing prototypes |
| `collect_legit_samples.py` | 5 KB | Collect legitimate website samples |
| `train_model.py` | 9 KB | ML model training pipeline |
| `tune_threshold.py` | 4 KB | NCD threshold tuning utility |

#### Scripts (`scripts/`)

| Script | Purpose |
|--------|---------|
| `generate_samples.py` | Generate DOM samples from URL lists (parallel processing) |
| `build_manifest.py` | Build dataset manifest JSON |
| `validate_samples.py` | Validate sample integrity and metadata |

---

## Technology Stack

### Backend Framework
- **Python 3.8+** - Core language
- **FastAPI 0.120.0** - Modern async web framework
- **Uvicorn 0.38.0** - ASGI server

### Web Rendering & HTML Processing
- **Selenium 4.27.1** - Browser automation
- **Chrome/ChromeDriver** - Headless browser
- **BeautifulSoup4 4.12.3** - HTML parsing
- **LXML 5.3.0** - Fast XML/HTML parser

### Data & Storage
- **SQLite** - Local PhishTank database
- **LZMA Compression** - NCD algorithm compression
- **JSON** - Configuration and metadata

### Intelligence & Networking
- **Requests 2.32.5** - HTTP client
- **python-whois 0.9.0** - Domain information
- **dnspython 2.6.1** - DNS lookups
- **SSL/TLS** - Certificate analysis

### Machine Learning
- **scikit-learn 1.5.2** - ML models (logistic regression, random forest)
- **numpy 2.3.5** - Numerical computing
- **scipy 1.16.3** - Scientific computing

### Utilities & Caching
- **python-dotenv 1.0.1** - Environment management
- **cachetools 5.5.0** - TTL-based caching

### Testing
- **pytest 8.3.3** - Testing framework
- **pytest-cov 6.0.0** - Coverage reporting
- **httpx 0.27.2** - HTTP client for testing

### Frontend
- **HTML5/CSS3** - Modern web standards
- **Vanilla JavaScript** - No framework dependencies
- **Responsive Design** - Mobile-friendly

---

## Detection Pipeline

### Phase 1: Signature Lookup (Fast Path)

```
URL Input
    │
    ▼
┌──────────────────────┐
│  Check TTL Cache     │
│  (1-hour default)    │
└──────────┬───────────┘
           │
    ┌──────┴──────┐
    │ Hit?         │ Miss
    ▼              ▼
Return      ┌──────────────────┐
Result      │ Query SQLite DB  │
            │ (< 1ms)          │
            └──────────┬───────┘
                       │
            ┌──────────┴──────────┐
            │ Found?               │ Not Found
            ▼                      ▼
        Return              Continue to
        Result              Phase 2
```

**Step-by-Step:**

1. **Cache Check** - Look for URL in in-memory TTL cache
   - If cached and valid → Return immediately
   - Cache hit rate: 70-90% for repeated lookups

2. **Local Database Query** - Query SQLite database
   - Location: `src/db_phishtank.sqlite`
   - Response time: < 1ms
   - Contains: 48,020 verified phishing URLs
   - Index: Optimized URL lookup

3. **Result Handling**
   - **Found & Verified** → Return immediately with high confidence
   - **Not Found** → Proceed to Phase 2 (NCD analysis)
   - **Error** → Fail-open policy, proceed to Phase 2

### Phase 2: NCD Structural Analysis (Fallback)

```
URL Input
    │
    ▼
┌──────────────────────┐
│ Render with Selenium │
│ (Chrome headless)    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Extract HTML DOM     │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Check DOM Size       │
└──────────┬───────────┘
           │
    ┌──────┴──────┐
    │ < 2KB?       │ >= 2KB
    ▼              ▼
Resource      DOM Structure
Signature     Analysis
Mode          Mode
    │              │
    └──────┬───────┘
           │
           ▼
┌──────────────────────┐
│ Sanitize HTML        │
│ (tags or tags+attrs) │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Compute NCD          │
│ (LZMA compression)   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Compare Against:     │
│ - Cluster 1 (phish)  │
│ - Cluster 2 (phish)  │
│ - Cluster 3 (phish)  │
│ - Legit prototypes   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Find Minimum NCD     │
│ Distance             │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Classification       │
│ Based on Threshold   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Gather OSINT Data    │
│ (parallel)           │
└──────────┬───────────┘
           │
           ▼
Return Result
```

**Step-by-Step:**

1. **DOM Extraction**
   - Render webpage using Selenium + Chrome (headless)
   - Extract HTML structure
   - Remove scripts, styles, and content

2. **Size Check**
   - If DOM < 2000 bytes → Use Resource Signature mode
   - Otherwise → Use DOM Structure mode

3. **Sanitization**
   - **Tags Only Mode** (default): Extract only HTML tags
     ```
     html head title body div span p ...
     ```
   - **Tags + Attributes Mode**: Include attributes
     ```
     html head:lang title body:class div:id div:class span p:style ...
     ```

4. **NCD Computation**
   ```
   NCD(x, y) = (C(xy) - min(C(x), C(y))) / max(C(x), C(y))
   ```
   Where:
   - `C(x)` = compressed size of x using LZMA
   - `C(xy)` = compressed size of concatenation
   - Lower NCD = more similar structures

5. **Classification**
   - Compare against clustered prototypes:
     - Cluster 1, 2, 3 (phishing)
     - Legitimate prototypes
   - Find minimum distance
   - If best_phish < best_legit AND best_phish < threshold (0.25)
     → **PHISHING**
   - Otherwise → **LEGITIMATE**

6. **OSINT Intelligence** (Parallel)
   - Domain age, registrar, nameservers
   - SSL certificate information
   - IP address and hosting provider
   - MX records

---

## API Endpoints

### `GET /detect`

**Main detection endpoint**

**Parameters:**
- `url` (required, string): Full URL to analyze (include http:// or https://)
- `skip_signature` (optional, boolean): Skip PhishTank lookup, go straight to NCD (default: false)

**Example Request:**
```bash
curl "http://127.0.0.1:8000/detect?url=https://example.com"
```

**Response (PhishTank Hit):**
```json
{
  "url": "http://known-phishing-site.com",
  "classification": "phish",
  "source": "signature-local",
  "confidence": "high",
  "phish_id": 12345,
  "detail_page": "https://phishtank.com/phish_detail.php?phish_id=12345",
  "submitted_at": "2024-01-01T12:00:00+00:00",
  "detection_id": "uuid-string"
}
```

**Response (NCD Fallback):**
```json
{
  "url": "https://example.com",
  "classification": "legit",
  "source": "ncd-clustered",
  "confidence": "medium",
  "ncd_score_phish": 0.5234,
  "ncd_score_legit": 0.1234,
  "closest_sample": "https://legitimate-site.com",
  "detection_mode": "dom-structure",
  "dom_length": 12345,
  "ip": "192.168.1.1",
  "registrar": "Example Registrar",
  "domain_age_days": 365,
  "ssl_enabled": true,
  "ssl_issuer": "Let's Encrypt",
  "reason": "DOM structure matches legitimate patterns",
  "feedback_url": "/feedback?id=uuid",
  "detection_id": "uuid-string"
}
```

### `GET /metrics`

**System metrics endpoint**

**Example Request:**
```bash
curl "http://127.0.0.1:8000/metrics"
```

**Response:**
```json
{
  "phishtank": {
    "lookup_count": 150,
    "hits": 42,
    "errors": 3,
    "cache_hits": 75,
    "local_db_hits": 20
  },
  "ncd": {
    "samples_loaded": 19
  },
  "feedback": {
    "total_submissions": 5
  }
}
```

### `GET /samples`

**Dataset statistics endpoint**

**Example Request:**
```bash
curl "http://127.0.0.1:8000/samples"
```

**Response:**
```json
{
  "samples": 19,
  "labels": {
    "phish": 10,
    "legit": 9
  },
  "examples": [
    "https://example1.com",
    "https://example2.com"
  ]
}
```

### `GET /feedback`

**User feedback collection endpoint**

**Parameters:**
- `detection_id` (required, string): Detection ID from /detect response
- `is_correct` (required, boolean): Was the classification correct?
- `comment` (optional, string): Additional feedback

**Example Request:**
```bash
curl "http://127.0.0.1:8000/feedback?detection_id=uuid&is_correct=true&comment=Correctly%20identified"
```

**Response:**
```json
{
  "status": "success",
  "message": "Feedback recorded",
  "feedback_id": "uuid"
}
```

---

## Configuration Guide

### Environment Variables (`.env`)

```bash
# Chrome Driver Configuration
# Download from: https://chromedriver.chromium.org/
CHROMEDRIVER_PATH=D:\Innovative Project\chromedriver-win64\chromedriver.exe

# API Configuration
API_HOST=127.0.0.1
API_PORT=8000

# Detection Parameters
DEFAULT_NCD_THRESHOLD=0.25
DEFAULT_WAIT_SECONDS=2
DEFAULT_HEADLESS=true

# Samples Directory
SAMPLES_DIR=samples

# PhishTank Configuration
# Path to local PhishTank SQLite database
PHISHTANK_DB_PATH=src/db_phishtank.sqlite

# Cache TTL in seconds (default: 1 hour)
PHISHTANK_CACHE_TTL=3600

# Optional: Machine Learning Configuration
ML_ENABLED=false
MODEL_PATH=models/model.pkl
MODEL_TYPE=logistic_regression
ML_CONFIDENCE_THRESHOLD=0.6

# Optional: NCD Classification Parameters
NCD_MIN_SEPARATION_MARGIN=0.02
NCD_CLOSE_MARGIN=0.05
NCD_ABSOLUTE_THRESHOLD=0.65
NCD_CONSERVATIVE_BIAS=true

# Optional: Minimal DOM Configuration
MINIMAL_DOM_THRESHOLD=300
MINIMAL_DOM_PENALTY=0.05
```

### Configuration Options Explained

| Variable | Default | Description |
|----------|---------|-------------|
| `CHROMEDRIVER_PATH` | N/A | Path to ChromeDriver executable |
| `API_HOST` | `127.0.0.1` | API server host (use 0.0.0.0 for external access) |
| `API_PORT` | `8000` | API server port |
| `DEFAULT_NCD_THRESHOLD` | `0.25` | NCD threshold for classification (lower = stricter) |
| `DEFAULT_WAIT_SECONDS` | `2` | Wait time for page rendering (seconds) |
| `DEFAULT_HEADLESS` | `true` | Run Chrome in headless mode |
| `SAMPLES_DIR` | `samples` | Directory for DOM samples |
| `PHISHTANK_DB_PATH` | `src/db_phishtank.sqlite` | Path to PhishTank database |
| `PHISHTANK_CACHE_TTL` | `3600` | Cache TTL in seconds |

---

## Database Details

### PhishTank Local Database

**Location**: `src/db_phishtank.sqlite`

**Statistics**:
- **Type**: SQLite 3
- **Size**: 21.92 MB
- **Entries**: 48,020 verified phishing URLs
- **Last Updated**: December 4, 2025
- **Update Frequency**: Recommended hourly

**Schema**:
```sql
CREATE TABLE phishtank_urls (
    phish_id INTEGER PRIMARY KEY,
    url TEXT UNIQUE NOT NULL,
    submission_time TEXT,
    target TEXT,
    updated_at TEXT NOT NULL
);

CREATE INDEX idx_url ON phishtank_urls(url);

CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT
);
```

**Metadata Fields**:
- `last_updated` - ISO timestamp of last update
- `entry_count` - Total number of entries

### Database Update

**Update Tool**: `tools/phishtank_update_local.py`

**Command**:
```bash
python tools/phishtank_update_local.py
```

**Process**:
1. Downloads PhishTank CSV from `https://data.phishtank.com/data/online-valid.csv`
2. Parses verified phishing URLs
3. Creates/updates SQLite database
4. Indexes URL column for fast lookups

**Output**:
```
2025-12-04 02:25:02,562 - INFO - Starting PhishTank database update
2025-12-04 02:25:02,563 - INFO - Downloading PhishTank CSV from https://data.phishtank.com/data/online-valid.csv
2025-12-04 02:25:11,470 - INFO - Downloaded 9615474 bytes
2025-12-04 02:25:11,473 - INFO - Parsing CSV content
2025-12-04 02:25:11,693 - INFO - Parsed 48028 verified phishing URLs
2025-12-04 02:25:14,146 - INFO - Database created at D:\...\src\db_phishtank.sqlite
2025-12-04 02:25:14,146 - INFO - Inserting 48028 entries into database
2025-12-04 02:25:16,460 - INFO - Successfully inserted 48028 entries
2025-12-04 02:25:16,471 - INFO - Update Complete!
2025-12-04 02:25:16,471 - INFO - Database: D:\...\src\db_phishtank.sqlite
2025-12-04 02:25:16,471 - INFO - Entries: 48,020
2025-12-04 02:25:16,471 - INFO - Size: 21.92 MB
```

### Database Info

**Command**:
```bash
python tools/phishtank_update_local.py --info
```

**Output**:
```
============================================================
PhishTank Local Database Info
============================================================
Path: D:\...\src\db_phishtank.sqlite
Entries: 48,020
Last Updated: 2025-12-04T02:25:16.471000
Size: 21.92 MB
============================================================
```

---

## Installation & Setup

### Prerequisites

- **Python 3.8+** - Download from [python.org](https://www.python.org/)
- **Chrome/Chromium** - Download from [google.com/chrome](https://www.google.com/chrome/)
- **ChromeDriver** - Download matching your Chrome version from [chromedriver.chromium.org](https://chromedriver.chromium.org/)

### Step 1: Clone Repository

```bash
git clone <repository-url>
cd phishing-ncd-detector
```

### Step 2: Create Virtual Environment

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

**Dependencies** (30 packages):
- FastAPI, Uvicorn - Web framework
- Selenium, BeautifulSoup4, LXML - Web processing
- Requests - HTTP client
- scikit-learn, numpy, scipy - ML/data processing
- pytest, pytest-cov, httpx - Testing
- python-dotenv, cachetools - Utilities
- python-whois, dnspython - OSINT

### Step 4: Download ChromeDriver

1. Visit [chromedriver.chromium.org](https://chromedriver.chromium.org/)
2. Download version matching your Chrome version
3. Extract to a known location (e.g., `D:\chromedriver-win64\chromedriver.exe`)

### Step 5: Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit .env and set CHROMEDRIVER_PATH
# Example: CHROMEDRIVER_PATH=D:\chromedriver-win64\chromedriver.exe
```

### Step 6: Update PhishTank Database

```bash
python tools/phishtank_update_local.py
```

This downloads the latest phishing URLs and builds the local database.

### Step 7: Start Server

```bash
python main.py
```

Or using uvicorn directly:
```bash
uvicorn src.api:app --reload --host 127.0.0.1 --port 8000
```

**Output**:
```
INFO:     Will watch for changes in these directories: ['D:\...']
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
INFO:     Started reloader process [11416] using WatchFiles
INFO:     Started server process [460]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
```

### Step 8: Access Dashboard

- **Dashboard**: http://127.0.0.1:8000/
- **API Docs**: http://127.0.0.1:8000/docs
- **ReDoc**: http://127.0.0.1:8000/redoc

---

## Usage Examples

### Web Dashboard

1. Open http://127.0.0.1:8000/ in your browser
2. Enter a URL in the detection field
3. Click "Analyze"
4. View results with classification, confidence, and OSINT data

### API Request (cURL)

```bash
# Basic detection
curl "http://127.0.0.1:8000/detect?url=https://example.com"

# Skip signature lookup
curl "http://127.0.0.1:8000/detect?url=https://example.com&skip_signature=true"

# Get metrics
curl "http://127.0.0.1:8000/metrics"

# Get samples
curl "http://127.0.0.1:8000/samples"
```

### Python Script

```python
import requests

# Detect URL
response = requests.get(
    "http://127.0.0.1:8000/detect",
    params={"url": "https://example.com"}
)
result = response.json()
print(f"Classification: {result['classification']}")
print(f"Confidence: {result['confidence']}")
print(f"Source: {result['source']}")

# Get metrics
metrics = requests.get("http://127.0.0.1:8000/metrics").json()
print(f"PhishTank lookups: {metrics['phishtank']['lookup_count']}")
print(f"Cache hits: {metrics['phishtank']['cache_hits']}")
```

### Generate Samples

```bash
# Add URLs to files
echo "https://phishing-site.com" >> urls-phish.txt
echo "https://legitimate-site.com" >> urls-legit.txt

# Generate samples
python scripts/generate_samples.py

# Validate samples
python scripts/validate_samples.py

# Build manifest
python scripts/build_manifest.py
```

### Update PhishTank Database

```bash
# Update database
python tools/phishtank_update_local.py

# View database info
python tools/phishtank_update_local.py --info
```

### Run Tests

```bash
# All tests
pytest tests/ -v

# Specific test
pytest tests/test_detector.py -v

# With coverage
pytest tests/ --cov=src --cov-report=html
```

---

## Performance Metrics

### Latency Comparison

| Method | Latency | Throughput | Use Case |
|--------|---------|------------|----------|
| PhishTank Cache | < 1ms | 100K+ req/s | Repeated lookups |
| PhishTank Local DB | < 1ms | 10K+ req/s | Production |
| PhishTank API | 100-500ms | ~50 req/s | Development |
| NCD Analysis | 2-5s | ~1 req/s | Unknown URLs |

### Performance Tips

1. **Use Local PhishTank Database** - 1000x faster than API lookups
2. **Enable Caching** - Default 1-hour TTL reduces repeated lookups by 70-90%
3. **Increase Sample Diversity** - More diverse NCD samples improve accuracy
4. **Tune NCD Threshold** - Adjust based on false positive/negative rates
5. **Parallel Processing** - Use ThreadPoolExecutor for batch operations
6. **Monitor Metrics** - Track PhishTank hit rates and cache effectiveness

### Optimization Strategies

**For High Throughput:**
- Use local PhishTank database (not API)
- Enable caching with appropriate TTL
- Run multiple API instances behind load balancer
- Use connection pooling for database

**For Accuracy:**
- Increase sample diversity
- Tune NCD threshold based on your use case
- Collect user feedback for continuous improvement
- Regularly update PhishTank database

---

## Security Features

### Input Validation
- All URLs validated before processing
- Malformed URLs rejected with clear error messages
- URL normalization for consistent lookups

### Headless Browser Mode
- Chrome runs in headless mode (no GUI)
- Prevents accidental user interaction
- Reduces resource consumption

### Fail-Open Policy
- System continues working if PhishTank unavailable
- Falls back to NCD analysis if signature lookup fails
- Graceful error handling with informative messages

### Sandboxed Execution
- Isolated browser execution per request
- Automatic cleanup of browser resources
- Timeout protection (configurable wait time)

### Error Handling & Logging
- Comprehensive error logging
- User-friendly error messages
- Detailed debug logs for troubleshooting
- No sensitive data in logs

### API Key Protection
- PhishTank API keys stored in environment variables
- Never committed to repository
- Secure .env file handling

### Database Security
- Local PhishTank database protection
- File permissions management
- Regular backups recommended

### Rate Limiting (Recommended for Production)
- Implement rate limiting for API endpoints
- Prevent abuse and DoS attacks
- Track usage per client

---

## Dashboard Features

### User Interface

**Theme**: Professional white-blue color scheme

**Components**:
- **URL Input Field** - Enter URL for analysis
- **Analyze Button** - Trigger detection
- **Result Card** - Classification and confidence display
- **Statistics Panel** - System metrics
- **OSINT Section** - Domain, SSL, hosting information
- **Feedback Section** - User accuracy feedback

### Result Display

**Color Coding**:
- 🟢 **Green** - Safe/Legitimate
- 🔴 **Red** - Phishing
- 🟡 **Yellow** - Suspicious/Unverified

**Information Displayed**:
- Classification (phish/legit/suspicious)
- Confidence level (high/medium/low)
- Detection source (signature/NCD)
- NCD scores (phishing vs legitimate)
- OSINT data (domain, SSL, IP, registrar)
- Detection ID (for feedback)

### Responsive Design

- **Desktop**: Full-width layout
- **Tablet**: Optimized for touch
- **Mobile**: Stacked layout

### Real-time Features

- Live URL analysis
- Instant results display
- Real-time metrics update
- Feedback submission

---

## Development Workflow

### 1. Add URLs

Add URLs to sample lists:

```bash
# Phishing URLs
echo "https://phishing-site-1.com" >> urls-phish.txt
echo "https://phishing-site-2.com" >> urls-phish.txt

# Legitimate URLs
echo "https://legitimate-site-1.com" >> urls-legit.txt
echo "https://legitimate-site-2.com" >> urls-legit.txt
```

### 2. Generate Samples

```bash
python scripts/generate_samples.py
```

This will:
- Process URLs in parallel
- Extract and sanitize DOMs
- Save `.dom` and `.meta.json` files to `samples/`

### 3. Validate Samples

```bash
python scripts/validate_samples.py
```

Checks:
- Sample file integrity
- Metadata validity
- Missing/invalid files

### 4. Build Manifest

```bash
python scripts/build_manifest.py
```

Creates `dataset_manifest.json` with:
- Sample counts
- Labels breakdown
- File listings

### 5. Update PhishTank Database

```bash
python tools/phishtank_update_local.py
```

Downloads latest phishing URLs and updates database.

### 6. Start Server

```bash
python main.py
```

### 7. Test

Access http://127.0.0.1:8000/ and test URLs.

### 8. Run Tests

```bash
pytest tests/ -v
```

---

## Testing

### Test Suite

Located in `tests/` directory:

| Test File | Purpose |
|-----------|---------|
| `test_api_integration.py` | API endpoint tests |
| `test_detector.py` | Detector logic tests |
| `test_ncd.py` | NCD computation tests |
| `test_phishtank_client.py` | PhishTank client tests |
| `test_sanitize.py` | HTML sanitization tests |
| `test_utils.py` | Utility function tests |

### Running Tests

```bash
# All tests
pytest tests/ -v

# Specific test file
pytest tests/test_detector.py -v

# Specific test function
pytest tests/test_detector.py::test_classification -v

# With coverage
pytest tests/ --cov=src --cov-report=html

# With markers
pytest tests/ -m "not slow" -v
```

### Test Configuration

File: `pytest.ini`

```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -v --tb=short
```

### Writing Tests

Example test:

```python
import pytest
from src.detector import classify_url

def test_phishing_detection():
    """Test phishing URL detection"""
    result = classify_url("https://phishing-site.com")
    assert result['classification'] == 'phish'
    assert result['confidence'] in ['high', 'medium', 'low']

def test_legitimate_detection():
    """Test legitimate URL detection"""
    result = classify_url("https://google.com")
    assert result['classification'] == 'legit'
```

---

## Troubleshooting

### Issue: ChromeDriver Not Found

**Error**: `The system cannot find the path specified`

**Solution**:
1. Download ChromeDriver from [chromedriver.chromium.org](https://chromedriver.chromium.org/)
2. Update `CHROMEDRIVER_PATH` in `.env`
3. Ensure path is correct and file is executable

### Issue: PhishTank Database Not Found

**Error**: `PhishTank database not found at ...`

**Solution**:
```bash
python tools/phishtank_update_local.py
```

This will download and create the database.

### Issue: Port Already in Use

**Error**: `Address already in use`

**Solution**:
```bash
# Change port in .env
API_PORT=8001

# Or kill process using port
# Windows:
netstat -ano | findstr :8000
taskkill /PID <PID> /F

# Linux/Mac:
lsof -i :8000
kill -9 <PID>
```

### Issue: Selenium Timeout

**Error**: `TimeoutException: Message: timeout`

**Solution**:
1. Increase `DEFAULT_WAIT_SECONDS` in `.env`
2. Check internet connection
3. Verify Chrome is installed
4. Try with `DEFAULT_HEADLESS=false` for debugging

### Issue: Low Detection Accuracy

**Solution**:
1. Update PhishTank database: `python tools/phishtank_update_local.py`
2. Increase sample diversity: Add more URLs to `urls-phish.txt` and `urls-legit.txt`
3. Tune NCD threshold: Adjust `DEFAULT_NCD_THRESHOLD` in `.env`
4. Collect user feedback for continuous improvement

### Issue: High False Positives

**Solution**:
1. Increase NCD threshold: `DEFAULT_NCD_THRESHOLD=0.35`
2. Add more legitimate samples
3. Check OSINT data for false positives
4. Review and adjust clustering

### Issue: High False Negatives

**Solution**:
1. Decrease NCD threshold: `DEFAULT_NCD_THRESHOLD=0.15`
2. Add more phishing samples
3. Update PhishTank database regularly
4. Review misclassified URLs

---

## Future Enhancements

### Planned Features

- **Machine Learning Integration** - Advanced ML models for better accuracy
- **Real-time Threat Intelligence** - Integration with threat feeds
- **Advanced Clustering** - Improved clustering algorithms
- **Docker Containerization** - Easy deployment
- **Rate Limiting** - API rate limiting
- **Authentication/Authorization** - User management
- **Multi-language Support** - International UI
- **Advanced Analytics** - Detailed analytics dashboard
- **Performance Optimization** - Further latency reduction
- **Batch API** - Bulk URL analysis

### Roadmap

**Phase 1** (Current):
- ✅ Hybrid detection system
- ✅ PhishTank integration
- ✅ NCD algorithm
- ✅ Web dashboard
- ✅ REST API

**Phase 2** (Planned):
- Machine learning models
- Advanced clustering
- Real-time threat feeds
- Docker support

**Phase 3** (Future):
- Rate limiting
- Authentication
- Multi-language
- Advanced analytics

---

## Support & Resources

### Documentation

- **README.md** - Main documentation
- **PROJECT_OVERVIEW.md** - Detailed overview
- **STRUCTURE.md** - Architecture details
- **PHISHTANK_INTEGRATION.md** - PhishTank setup
- **COMPREHENSIVE_GUIDE.md** - This file

### External Resources

- **FastAPI Documentation**: https://fastapi.tiangolo.com/
- **Selenium Documentation**: https://selenium.dev/documentation/
- **PhishTank**: https://www.phishtank.com/
- **ChromeDriver**: https://chromedriver.chromium.org/
- **Python Documentation**: https://docs.python.org/3/

### Getting Help

1. Check documentation files
2. Review test files for usage examples
3. Check API documentation at `/docs` endpoint
4. Review error logs for details
5. Check GitHub issues (if applicable)

---

## License

[Add your license information here]

---

## Acknowledgments

- NCD algorithm based on compression-based similarity
- Uses LZMA compression for optimal results
- Built with FastAPI, Selenium, and BeautifulSoup
- PhishTank for phishing URL database

---

**Project Status**: Production Ready | **Version**: 2.0.0 | **Last Updated**: December 4, 2025
