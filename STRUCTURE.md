# Project Structure Documentation

## Overview

This document describes the improved structure of the phishing detection system.

## Directory Layout

```
phishing-ncd-detector/
│
├── src/                          # Core application code
│   ├── __init__.py              # Package initialization
│   ├── api.py                   # FastAPI REST API endpoints
│   ├── config.py                # Configuration management (NEW)
│   ├── detector.py              # Main detection logic
│   ├── extract_dom.py           # DOM extraction pipeline
│   ├── ncd.py                   # NCD computation with caching
│   ├── render.py                # Selenium web rendering
│   ├── sanitize.py              # HTML sanitization functions
│   ├── save.py                  # Sample persistence utilities
│   └── utils.py                 # Common utility functions (NEW)
│
├── scripts/                      # Utility scripts (REORGANIZED)
│   ├── __init__.py              # Package initialization
│   ├── build_manifest.py        # Build dataset manifest
│   ├── generate_samples.py      # Generate DOM samples from URLs
│   └── validate_samples.py      # Validate sample integrity
│
├── tests/                        # Test suite (NEW)
│   ├── __init__.py              # Test package initialization
│   ├── conftest.py              # Pytest fixtures and configuration
│   ├── test_detector.py         # Detector module tests
│   ├── test_ncd.py              # NCD computation tests
│   ├── test_sanitize.py         # Sanitization tests
│   └── test_utils.py            # Utility function tests
│
├── samples/                      # DOM samples directory
│   ├── *.dom                    # Binary DOM files
│   └── *.meta.json              # Metadata files
│
├── web/                          # Web dashboard
│   └── index.html               # Dashboard HTML
│
├── .env.example                  # Environment template (NEW)
├── .gitignore                    # Git ignore rules (NEW)
├── main.py                       # Main entry point (NEW)
├── pytest.ini                    # Pytest configuration (NEW)
├── README.md                     # Comprehensive documentation (UPDATED)
├── requirements.txt              # Python dependencies (NEW)
├── STRUCTURE.md                  # This file (NEW)
├── dataset_manifest.json         # Dataset manifest
├── urls-legit.txt               # Legitimate URL list
└── urls-phish.txt               # Phishing URL list
```

## Key Improvements

### 1. Configuration Management (`src/config.py`)
- Centralized configuration using environment variables
- Default values for all settings
- Path management using pathlib
- Easy to modify without changing code

### 2. Utility Module (`src/utils.py`)
- Common functions extracted from multiple files
- Reusable URL loading function
- Directory management utilities

### 3. Scripts Organization
- All scripts moved to dedicated `scripts/` directory
- Improved error handling and logging
- Better documentation
- Consistent coding style

### 4. Code Quality Improvements
- **Removed duplication**: NCD logic consolidated in `ncd.py`
- **Type hints**: Added throughout codebase
- **Docstrings**: Comprehensive documentation for all functions
- **Error handling**: Better exception handling and user feedback

### 5. Testing Infrastructure
- Complete test suite with pytest
- Unit tests for core modules
- Fixtures for common test data
- Configuration for test discovery

### 6. Documentation
- Comprehensive README with setup instructions
- API endpoint documentation
- Usage examples
- Configuration guide

### 7. Development Tools
- `.env.example` for easy setup
- `.gitignore` to prevent committing sensitive files
- `pytest.ini` for test configuration
- `main.py` for easy server startup

## Module Responsibilities

### Core Modules (`src/`)

**api.py**
- FastAPI application setup
- REST API endpoints
- Request/response handling

**config.py**
- Environment variable loading
- Configuration constants
- Path management

**detector.py**
- Dataset loading
- URL classification
- NCD-based detection logic

**extract_dom.py**
- DOM extraction pipeline
- Sanitization mode selection
- Integration of render and sanitize

**ncd.py**
- NCD computation
- Compression size calculation
- Caching for performance

**render.py**
- Selenium WebDriver setup
- Page rendering
- Chrome options configuration

**sanitize.py**
- HTML parsing
- Tag extraction
- Attribute extraction

**save.py**
- DOM file persistence
- Metadata generation
- File naming conventions

**utils.py**
- URL file loading
- Directory management
- Common helper functions

### Scripts (`scripts/`)

**build_manifest.py**
- Scans samples directory
- Creates dataset manifest JSON
- Validates metadata

**generate_samples.py**
- Processes URL lists
- Parallel DOM extraction
- Sample generation with labels

**validate_samples.py**
- Checks sample integrity
- Validates metadata
- Reports missing/invalid files

## Configuration Files

**.env**
- Environment-specific settings
- ChromeDriver path
- API configuration
- Detection parameters

**requirements.txt**
- Python package dependencies
- Version specifications
- Testing dependencies

**pytest.ini**
- Test discovery patterns
- Test markers
- Pytest options

**.gitignore**
- Excludes virtual environments
- Ignores generated samples
- Prevents committing sensitive data

## Best Practices Applied

1. **Separation of Concerns**: Each module has a single, clear responsibility
2. **DRY Principle**: No code duplication
3. **Configuration Management**: Environment-based configuration
4. **Type Safety**: Type hints throughout
5. **Documentation**: Comprehensive docstrings
6. **Testing**: Unit tests for core functionality
7. **Error Handling**: Graceful error handling with informative messages
8. **Logging**: Consistent logging for debugging
9. **Code Style**: Consistent formatting and naming conventions
10. **Modularity**: Easy to extend and maintain

## Migration Notes

### Old Structure → New Structure

- `build_manifest.py` (root) → `scripts/build_manifest.py`
- `generate_samples.py` (root) → `scripts/generate_samples.py`
- `validate_samples.py` (root) → `scripts/validate_samples.py`
- `compression_check.py` (empty) → Removed
- NCD logic in `detector.py` → Consolidated in `ncd.py`
- Hardcoded paths → `config.py`
- Scattered utilities → `utils.py`

### Breaking Changes

None - All existing functionality preserved with improved organization.

## Future Enhancements

1. Add more comprehensive integration tests
2. Implement caching for API responses
3. Add database support for samples
4. Create CLI interface
5. Add monitoring and metrics
6. Implement rate limiting
7. Add authentication for API
8. Create Docker containerization
