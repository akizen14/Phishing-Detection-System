# AI-Driven Phishing Detection System

A phishing detection system using **Normalized Compression Distance (NCD)** to compare DOM structures of websites. This approach identifies phishing sites by measuring structural similarity to known legitimate and phishing websites.

## 🎯 Features

- **Hybrid Detection**: PhishTank signature lookup + NCD-based DOM analysis
- **Fast Signature Matching**: Check against PhishTank's verified phishing database
- **DOM Sanitization**: Extracts structural features while removing content
- **REST API**: FastAPI-powered detection service with metrics
- **Local Dump Support**: Optional offline PhishTank database for high throughput
- **Intelligent Caching**: TTL-based caching to reduce API calls
- **Web Dashboard**: Simple interface for testing URLs
- **Batch Processing**: Generate samples from URL lists in parallel
- **Configurable**: Environment-based configuration management

## 📋 Requirements

- Python 3.8+
- Chrome/Chromium browser
- ChromeDriver (matching your Chrome version)

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd phishing-ncd-detector
```

### 2. Create Virtual Environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Download ChromeDriver

Download ChromeDriver from [https://chromedriver.chromium.org/](https://chromedriver.chromium.org/) matching your Chrome version.

### 5. Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit .env and set CHROMEDRIVER_PATH
# Example: CHROMEDRIVER_PATH=C:\path\to\chromedriver.exe
```

## 📁 Project Structure

```
phishing-ncd-detector/
├── src/                      # Core source code
│   ├── api.py               # FastAPI application
│   ├── detector.py          # Detection logic
│   ├── ncd.py               # NCD computation
│   ├── extract_dom.py       # DOM extraction pipeline
│   ├── render.py            # Selenium rendering
│   ├── sanitize.py          # HTML sanitization
│   ├── save.py              # Sample persistence
│   ├── config.py            # Configuration management
│   └── utils.py             # Utility functions
├── scripts/                 # Utility scripts
│   ├── generate_samples.py  # Generate DOM samples
│   ├── build_manifest.py    # Build dataset manifest
│   └── validate_samples.py  # Validate samples
├── samples/                 # DOM samples (.dom + .meta.json)
├── web/                     # Web dashboard
│   └── index.html
├── tests/                   # Test suite
├── urls-phish.txt          # Phishing URL list
├── urls-legit.txt          # Legitimate URL list
├── requirements.txt        # Python dependencies
├── .env.example            # Environment template
└── README.md               # This file
```

## 🔧 Usage

### Generate Samples

Create DOM samples from URL lists:

```bash
# Add URLs to urls-phish.txt and urls-legit.txt
# Then run:
python scripts/generate_samples.py
```

This will:
- Process URLs in parallel
- Extract and sanitize DOMs
- Save `.dom` and `.meta.json` files to `samples/`

### Validate Samples

Check sample integrity:

```bash
python scripts/validate_samples.py
```

### Build Manifest

Create a dataset manifest:

```bash
python scripts/build_manifest.py
```

### Start API Server

```bash
# Using uvicorn directly
uvicorn src.api:app --reload --host 0.0.0.0 --port 8000

# Or with Python
python -m uvicorn src.api:app --reload
```

API will be available at:
- **Dashboard**: http://localhost:8000/
- **API Docs**: http://localhost:8000/docs
- **Detection Endpoint**: http://localhost:8000/detect?url=<URL>

### API Endpoints

#### `GET /detect`

Classify a URL as phishing or legitimate using hybrid detection.

**Detection Flow:**
1. Check PhishTank signature database (fast, high-confidence)
2. If not found or error, fall back to DOM/NCD analysis

**Parameters:**
- `url` (required): Full URL to analyze (include http:// or https://)
- `threshold` (optional): NCD threshold (default: 0.25)
- `skip_signature` (optional): Skip PhishTank lookup (default: false)

**Example - PhishTank Hit:**
```bash
curl "http://localhost:8000/detect?url=http://known-phishing-site.com"
```

**Response (PhishTank verified):**
```json
{
  "url": "http://known-phishing-site.com",
  "classification": "phish",
  "source": "phishtank",
  "confidence": "high",
  "phish_id": 12345,
  "detail_page": "https://phishtank.com/phish_detail.php?phish_id=12345",
  "submitted_at": "2024-01-01T12:00:00+00:00"
}
```

**Response (NCD fallback):**
```json
{
  "url": "https://example.com",
  "classification": "legit",
  "source": "ncd",
  "confidence": "medium",
  "ncd": 0.1234,
  "closest_sample": "https://legitimate-site.com"
}
```

#### `GET /samples`

Get dataset statistics.

**Response:**
```json
{
  "samples": 19,
  "labels": {
    "phish": 10,
    "legit": 9
  },
  "examples": ["https://...", "..."]
}
```

#### `GET /metrics`

Get system metrics including PhishTank statistics.

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
  }
}
```

## 🧪 How It Works

### Hybrid Detection Pipeline

#### Phase 1: PhishTank Signature Lookup (Fast Path)
1. **Check Cache**: Look for URL in TTL cache (1-hour default)
2. **Local Database** (if enabled): Query SQLite database for instant results
3. **API Lookup** (fallback): POST to PhishTank API with retry logic
4. **Result**:
   - **Verified Phish** → Return immediately with high confidence
   - **Unverified** → Mark suspicious, continue to NCD
   - **Not Found/Error** → Continue to NCD (fail-open policy)

#### Phase 2: DOM/NCD Analysis (Fallback)

**1. DOM Extraction**
- Renders webpage using Selenium
- Extracts HTML structure
- Removes scripts, styles, and content

**2. Sanitization Modes**

**Tags Only** (default):
```
html head title body div span p ...
```

**Tags + Attributes**:
```
html head:lang title body:class div:id div:class span p:style ...
```

**3. NCD Computation**

Normalized Compression Distance measures similarity:

```
NCD(x, y) = (C(xy) - min(C(x), C(y))) / max(C(x), C(y))
```

Where:
- `C(x)` = compressed size of x
- `C(xy)` = compressed size of concatenation
- Lower NCD = more similar

**4. Classification**

- Compare target URL's DOM with all samples
- Find minimum NCD distance
- If distance > threshold → classify as phishing
- Otherwise → use label of closest sample

## ⚙️ Configuration

Edit `.env` file:

```bash
# Chrome Driver
CHROMEDRIVER_PATH=/path/to/chromedriver

# API Settings
API_HOST=0.0.0.0
API_PORT=8000

# Detection Parameters
DEFAULT_NCD_THRESHOLD=0.25
DEFAULT_WAIT_SECONDS=2
DEFAULT_HEADLESS=true

# Directories
SAMPLES_DIR=samples

# PhishTank Configuration
PHISHTANK_API_KEY=                    # Optional for low volume
PHISHTANK_USE_LOCAL_DUMP=false        # Enable for production
PHISHTANK_DUMP_PATH=data/phishtank.db # Local database path
PHISHTANK_CACHE_TTL=3600               # Cache TTL in seconds
```

### PhishTank Setup

#### Option 1: API Mode (Development)

For low-volume testing (< 10,000 requests/day):

```bash
# No API key needed for basic usage
PHISHTANK_USE_LOCAL_DUMP=false
```

For higher volume, get a free API key:
1. Register at https://www.phishtank.com/api_register.php
2. Add to `.env`: `PHISHTANK_API_KEY=your_key_here`

#### Option 2: Local Dump Mode (Production - Recommended)

For high throughput and offline operation:

**1. Download and Build Database:**
```bash
# Create data directory
mkdir -p data

# Download PhishTank dump and build SQLite database
python tools/phishtank_update.py

# Verify database
python tools/phishtank_update.py --info
```

**2. Enable in Configuration:**
```bash
PHISHTANK_USE_LOCAL_DUMP=true
PHISHTANK_DUMP_PATH=data/phishtank.db
```

**3. Schedule Hourly Updates (Cron):**
```bash
# Edit crontab
crontab -e

# Add hourly update (runs at minute 0 of every hour)
0 * * * * cd /path/to/phishing-ncd-detector && /path/to/venv/bin/python tools/phishtank_update.py >> logs/phishtank_update.log 2>&1
```

**Windows Task Scheduler:**
```powershell
# Create scheduled task for hourly updates
schtasks /create /tn "PhishTank Update" /tr "C:\path\to\venv\Scripts\python.exe C:\path\to\project\tools\phishtank_update.py" /sc hourly /st 00:00
```

**Benefits of Local Dump:**
- ✅ No API rate limits
- ✅ Instant lookups (< 1ms)
- ✅ Works offline
- ✅ No external dependencies during detection
- ✅ Handles unlimited throughput

## 🧪 Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test modules
pytest tests/test_phishtank_client.py -v
pytest tests/test_api_integration.py -v

# With coverage
python -m pytest tests/ --cov=src --cov-report=html

# Run PhishTank demo
python demo_phishtank.py
```

## 📊 Performance Tips

1. **Use Local PhishTank Database**: 1000x faster than API lookups (< 1ms vs 100-500ms)
2. **Enable Caching**: Default 1-hour TTL reduces repeated lookups by 70-90%
3. **Sample Size**: More diverse NCD samples improve accuracy
4. **Threshold Tuning**: Adjust NCD threshold based on false positive/negative rates
5. **Parallel Processing**: Use ThreadPoolExecutor for batch operations
6. **Monitor Metrics**: Track PhishTank hit rates and cache effectiveness

### Performance Comparison

| Mode | Latency | Throughput | Best For |
|------|---------|------------|----------|
| PhishTank API | 100-500ms | ~50 req/s | Development |
| PhishTank Local DB | < 1ms | 10,000+ req/s | Production |
| NCD Analysis | 2-5s | ~1 req/s | Unknown URLs |

## 🔒 Security Notes

- **API Keys**: Never commit PhishTank API keys to repository (use `.env`)
- **Fail-Open Policy**: System continues working if PhishTank is unavailable
- **Sandboxing**: Never run untrusted URLs without proper sandboxing
- **ChromeDriver**: Runs in headless mode by default for security
- **Rate Limiting**: Consider adding rate limiting for production deployments
- **Input Validation**: All URLs are validated before processing
- **Database Security**: Protect local PhishTank database from unauthorized access

## 📚 Additional Documentation

- **[PhishTank Integration Guide](PHISHTANK_INTEGRATION.md)** - Detailed PhishTank setup and usage
- **[Project Structure](STRUCTURE.md)** - Architecture and module organization

## 📝 License

[Add your license here]

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📧 Contact

[Add your contact information]

## 🙏 Acknowledgments

- NCD algorithm based on compression-based similarity
- Uses LZMA compression for optimal results
- Built with FastAPI, Selenium, and BeautifulSoup
