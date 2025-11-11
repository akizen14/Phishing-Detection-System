# PhishTank Quick Start Guide

## 🚀 5-Minute Setup

### Step 1: Install Dependencies (30 seconds)
```bash
pip install cachetools requests
```

### Step 2: Configure (30 seconds)
```bash
# Copy environment template
cp .env.example .env

# For development: No changes needed!
# For production: Set PHISHTANK_USE_LOCAL_DUMP=true
```

### Step 3: Test It (1 minute)
```bash
# Run demo
python demo_phishtank.py

# Start API
python main.py

# Test endpoint
curl "http://localhost:8000/detect?url=http://google.com"
```

### Step 4: Setup Local Database (2 minutes - Optional)
```bash
mkdir -p data
python tools/phishtank_update.py
```

### Step 5: Schedule Updates (1 minute - Optional)
```bash
# Linux/Mac
crontab -e
# Add: 0 * * * * cd /path/to/project && python tools/phishtank_update.py

# Windows
schtasks /create /tn "PhishTank Update" /tr "python tools/phishtank_update.py" /sc hourly
```

## 📝 Cheat Sheet

### Environment Variables
```bash
PHISHTANK_API_KEY=              # Optional
PHISHTANK_USE_LOCAL_DUMP=false  # true for production
PHISHTANK_DUMP_PATH=data/phishtank.db
PHISHTANK_CACHE_TTL=3600        # 1 hour
```

### API Endpoints
```bash
# Detect with PhishTank
GET /detect?url=http://example.com

# Skip PhishTank (NCD only)
GET /detect?url=http://example.com&skip_signature=true

# Check metrics
GET /metrics
```

### Python Usage
```python
from src.phishtank_client import phishtank_lookup

# Lookup URL
result = phishtank_lookup("http://test.com")

# Check result
if result['verified']:
    print(f"Phishing! ID: {result['phish_id']}")
```

### CLI Commands
```bash
# Update database
python tools/phishtank_update.py

# Check database info
python tools/phishtank_update.py --info

# Run tests
pytest tests/test_phishtank_client.py -v

# Run demo
python demo_phishtank.py
```

## 🎯 Common Tasks

### Check if PhishTank is Working
```bash
curl "http://localhost:8000/metrics"
# Look for: phishtank.lookup_count > 0
```

### Force Cache Clear
```python
from src.phishtank_client import clear_cache
clear_cache()
```

### Check Database Status
```bash
python tools/phishtank_update.py --info
```

### Test Specific URL
```bash
curl "http://localhost:8000/detect?url=YOUR_URL_HERE"
```

## 🐛 Troubleshooting

### Issue: "PhishTank lookup error"
```bash
# Solution: Enable local database
python tools/phishtank_update.py
# Edit .env: PHISHTANK_USE_LOCAL_DUMP=true
```

### Issue: "Database not found"
```bash
# Solution: Create database
mkdir -p data
python tools/phishtank_update.py
```

### Issue: High error rate
```bash
# Check metrics
curl "http://localhost:8000/metrics"

# Solution: Use local database or add API key
```

## 📊 Performance Modes

| Mode | Setup | Speed | Best For |
|------|-------|-------|----------|
| **API** | None | 100-500ms | Development |
| **Local DB** | 2 min | < 1ms | Production |

## ✅ Verification Checklist

- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] `.env` file configured
- [ ] Demo script runs successfully
- [ ] API server starts
- [ ] `/detect` endpoint works
- [ ] `/metrics` shows PhishTank stats
- [ ] Tests pass (`pytest tests/test_phishtank_client.py`)
- [ ] Local database created (optional)
- [ ] Cron job scheduled (optional)

## 🎓 Learn More

- **Detailed Guide**: [PHISHTANK_INTEGRATION.md](PHISHTANK_INTEGRATION.md)
- **Full Summary**: [PHISHTANK_SUMMARY.md](PHISHTANK_SUMMARY.md)
- **Main Docs**: [README.md](README.md)

## 💡 Pro Tips

1. **Start Simple**: Use API mode first, switch to local DB later
2. **Monitor Metrics**: Check `/metrics` endpoint regularly
3. **Cache is Your Friend**: Default 1-hour TTL is usually good
4. **Update Regularly**: Schedule hourly database updates
5. **Test Thoroughly**: Run `demo_phishtank.py` after changes

## 🆘 Need Help?

1. Check [PHISHTANK_INTEGRATION.md](PHISHTANK_INTEGRATION.md) troubleshooting section
2. Run demo script: `python demo_phishtank.py`
3. Check logs for specific errors
4. Verify environment variables in `.env`
5. Test with known URLs first

---

**That's it!** You now have PhishTank signature-based detection integrated with your phishing detector. 🎉
