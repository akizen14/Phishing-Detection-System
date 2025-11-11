# PhishTank Integration Guide

## Overview

This document provides detailed information about the PhishTank signature-based lookup integration in the phishing detection system.

## Architecture

### Components

1. **`src/phishtank_client.py`** - Core PhishTank client
   - API lookup with retry logic
   - Local database support
   - TTL-based caching
   - Metrics collection

2. **`tools/phishtank_update.py`** - Database updater
   - Downloads PhishTank dumps
   - Builds SQLite database
   - Scheduled updates support

3. **`src/api.py`** - API integration
   - Hybrid detection flow
   - Fail-open policy
   - Confidence scoring

## Detection Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    URL Detection Request                     │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │  skip_signature=?    │
              └──────────┬───────────┘
                         │
         ┌───────────────┴───────────────┐
         │ No                            │ Yes
         ▼                               ▼
┌────────────────────┐          ┌────────────────┐
│ PhishTank Lookup   │          │  Skip to NCD   │
└─────────┬──────────┘          └────────────────┘
          │
          ▼
┌────────────────────┐
│  Check TTL Cache   │
└─────────┬──────────┘
          │
          ├─── Cache Hit ──────────────────┐
          │                                 │
          ├─── Cache Miss                   │
          │         │                       │
          │         ▼                       │
          │  ┌──────────────────┐          │
          │  │ USE_LOCAL_DUMP?  │          │
          │  └────────┬─────────┘          │
          │           │                     │
          │  ┌────────┴────────┐           │
          │  │ Yes             │ No        │
          │  ▼                 ▼           │
          │ ┌────────┐   ┌─────────┐      │
          │ │ SQLite │   │ API POST│      │
          │ │ Query  │   │ Lookup  │      │
          │ └────┬───┘   └────┬────┘      │
          │      │            │            │
          │      └────────┬───┘            │
          │               │                │
          └───────────────┴────────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Parse Result        │
              └───────────┬───────────┘
                          │
          ┌───────────────┼───────────────┐
          │               │               │
          ▼               ▼               ▼
    ┌─────────┐    ┌──────────┐    ┌─────────┐
    │Verified │    │Unverified│    │Not Found│
    │  Phish  │    │  Phish   │    │  /Error │
    └────┬────┘    └─────┬────┘    └────┬────┘
         │               │               │
         ▼               ▼               ▼
    ┌─────────┐    ┌──────────┐    ┌─────────┐
    │ Return  │    │Run NCD + │    │Run NCD  │
    │  Phish  │    │ Return   │    │Analysis │
    │High Conf│    │Suspicious│    │         │
    └─────────┘    └──────────┘    └─────────┘
```

## Configuration Options

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PHISHTANK_API_KEY` | `""` | API key (optional for low volume) |
| `PHISHTANK_USE_LOCAL_DUMP` | `false` | Enable local database mode |
| `PHISHTANK_DUMP_PATH` | `data/phishtank.db` | Path to SQLite database |
| `PHISHTANK_CACHE_TTL` | `3600` | Cache TTL in seconds (1 hour) |

### API Modes

#### Mode 1: Direct API (Development)

**Pros:**
- No setup required
- Always up-to-date
- Simple configuration

**Cons:**
- Rate limits apply
- Network dependency
- Slower (100-500ms per lookup)

**Best for:** Development, testing, low-volume deployments

#### Mode 2: Local Database (Production)

**Pros:**
- No rate limits
- Ultra-fast (< 1ms)
- Works offline
- Unlimited throughput

**Cons:**
- Requires initial setup
- Needs periodic updates
- Slightly stale data (up to 1 hour)

**Best for:** Production, high-volume, offline deployments

## Setup Instructions

### Quick Start (API Mode)

```bash
# 1. No configuration needed for basic usage
# Just ensure PhishTank client is imported

# 2. Test it
python demo_phishtank.py
```

### Production Setup (Local Database)

```bash
# 1. Create data directory
mkdir -p data

# 2. Download and build database
python tools/phishtank_update.py

# 3. Verify database
python tools/phishtank_update.py --info

# 4. Update .env
echo "PHISHTANK_USE_LOCAL_DUMP=true" >> .env

# 5. Test it
python demo_phishtank.py

# 6. Schedule hourly updates (Linux/Mac)
crontab -e
# Add: 0 * * * * cd /path/to/project && /path/to/venv/bin/python tools/phishtank_update.py

# 6. Schedule hourly updates (Windows)
schtasks /create /tn "PhishTank Update" /tr "C:\path\to\venv\Scripts\python.exe C:\path\to\project\tools\phishtank_update.py" /sc hourly
```

## API Usage

### Basic Detection

```python
import requests

# Will check PhishTank first, then fall back to NCD
response = requests.get(
    "http://localhost:8000/detect",
    params={"url": "http://suspicious-site.com"}
)

result = response.json()
print(f"Classification: {result['classification']}")
print(f"Source: {result['source']}")
print(f"Confidence: {result['confidence']}")
```

### Skip Signature Lookup

```python
# Go straight to NCD analysis
response = requests.get(
    "http://localhost:8000/detect",
    params={
        "url": "http://test-site.com",
        "skip_signature": True
    }
)
```

### Check Metrics

```python
response = requests.get("http://localhost:8000/metrics")
metrics = response.json()

print(f"PhishTank lookups: {metrics['phishtank']['lookup_count']}")
print(f"PhishTank hits: {metrics['phishtank']['hits']}")
print(f"Cache hits: {metrics['phishtank']['cache_hits']}")
```

## Programmatic Usage

### Direct Client Usage

```python
from src.phishtank_client import phishtank_lookup, get_metrics

# Lookup a URL
result = phishtank_lookup("http://example.com")

if result['verified']:
    print(f"Verified phishing site!")
    print(f"PhishTank ID: {result['phish_id']}")
    print(f"Details: {result['detail_page']}")
else:
    print("Not in PhishTank database")

# Check metrics
metrics = get_metrics()
print(f"Total lookups: {metrics['lookup_count']}")
```

### Cache Management

```python
from src.phishtank_client import clear_cache, reset_metrics

# Clear cache (force fresh lookups)
clear_cache()

# Reset metrics counters
reset_metrics()
```

## Performance Characteristics

### API Mode

- **Latency**: 100-500ms per lookup
- **Throughput**: ~10-50 requests/second (with caching)
- **Rate Limit**: Varies by API key tier
- **Cache Hit Rate**: 60-80% typical

### Local Database Mode

- **Latency**: < 1ms per lookup
- **Throughput**: 10,000+ requests/second
- **Rate Limit**: None
- **Cache Hit Rate**: 90%+ (most lookups hit local DB)

### Cache Effectiveness

With default 1-hour TTL:
- Repeated URL checks are instant
- Reduces API calls by 70-90%
- Memory usage: ~10MB for 10,000 cached entries

## Monitoring & Metrics

### Available Metrics

```json
{
  "lookup_count": 1000,      // Total lookups performed
  "hits": 150,               // Verified phishing URLs found
  "errors": 5,               // API/database errors
  "cache_hits": 600,         // Lookups served from cache
  "local_db_hits": 200       // Lookups served from local DB
}
```

### Monitoring Recommendations

1. **Alert on high error rate**: `errors / lookup_count > 0.05`
2. **Monitor cache hit rate**: `cache_hits / lookup_count < 0.5` may indicate cache issues
3. **Track PhishTank hit rate**: `hits / lookup_count` for detection effectiveness
4. **Database freshness**: Check last_updated timestamp

## Troubleshooting

### Issue: "PhishTank lookup error"

**Cause**: Network error, rate limit, or invalid API key

**Solution**:
1. Check network connectivity
2. Verify API key (if using)
3. Enable local database mode
4. Check logs for specific error

### Issue: "Local database not found"

**Cause**: Database file doesn't exist

**Solution**:
```bash
python tools/phishtank_update.py
```

### Issue: High API error rate

**Cause**: Rate limiting or network issues

**Solution**:
1. Enable local database mode
2. Increase cache TTL
3. Add API key for higher limits

### Issue: Stale database

**Cause**: Update script not running

**Solution**:
1. Verify cron/scheduled task is active
2. Check update logs
3. Run manual update: `python tools/phishtank_update.py`

## Testing

### Unit Tests

```bash
# Run PhishTank client tests
pytest tests/test_phishtank_client.py -v

# Run integration tests
pytest tests/test_api_integration.py -v
```

### Manual Testing

```bash
# Run demo script
python demo_phishtank.py

# Test specific URL
curl "http://localhost:8000/detect?url=http://test.com"

# Check metrics
curl "http://localhost:8000/metrics"
```

## Security Considerations

1. **API Key Storage**: Never commit API keys to repository
2. **Fail-Open Policy**: System continues working if PhishTank is unavailable
3. **Input Validation**: URLs are validated before lookup
4. **Rate Limiting**: Consider adding rate limiting to prevent abuse
5. **Database Security**: Protect local database file from unauthorized access

## Best Practices

1. **Use local database in production** for reliability and performance
2. **Schedule hourly updates** to keep database fresh
3. **Monitor metrics** to track system health
4. **Set appropriate cache TTL** based on your needs
5. **Implement logging** for audit trails
6. **Test failover** scenarios regularly

## References

- PhishTank API Documentation: https://www.phishtank.com/api_info.php
- PhishTank Developer Forum: https://www.phishtank.com/developer_info.php
- Data Dumps: http://data.phishtank.com/
