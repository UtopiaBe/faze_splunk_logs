# Project Structure

FAZE Security API integration organized by functional area.

## Directory Layout

```
.
├── agentic_red_team/           # Agentic Red Team (ART) API integration
│   ├── fetch_agentic_red_team_vulns.py    # ⭐ Main script: fetch all vulns by asset
│   ├── fetch_agentic_red_team.py          # Fetch last 20 vulns
│   ├── fetch_all_assets_vulns.py          # Fetch all assets with vulns
│   ├── fetch_assets_and_vulns.py          # Combined assets + vulns fetcher
│   ├── run_red_team_scan.py               # Automated scan runner
│   ├── discover_endpoints.py              # Test endpoint variations
│   └── AGENTIC_RED_TEAM_GUIDE.md          # Complete ART guide
│
├── splunk/                     # Splunk integration & addons
│   ├── addons/                 # Splunk addon scripts
│   │   ├── faze_security_addon.py         # ⭐ Main Splunk addon (ART + dedup support)
│   │   ├── faze_comprehensive_addon.py    # Comprehensive multi-endpoint addon
│   │   └── agentic_red_team_input.py      # Synthetic vulnerability generator
│   ├── config/
│   │   └── ADDON_CONFIG.md                # Splunk addon configuration guide
│   └── utils/
│       └── splunk_log_explorer.py         # Splunk log exploration tool
│
├── scripts/                    # Test & utility scripts
│   ├── test_getart.py                     # Test GetArtVulnerabilities endpoint
│   ├── test_art_vulns.py                  # Test ART vulns with pagination
│   ├── test_api.py                        # General API tests
│   ├── test_faze_integration.py           # Integration tests
│   ├── fetch_logs.py                      # Generic log fetcher
│   ├── debug_api.py                       # API debugging utility
│   └── COMPREHENSIVE_API_GUIDE.md         # API reference
│
├── output/                     # Generated data files
│   ├── all_assets.jsonl                   # 121 FAZE assets (JSON Lines)
│   └── agentic_red_team_vulns.jsonl       # 1,069 vulnerabilities (JSON Lines)
│
├── config/                     # Configuration & credentials
│   └── .env                                # Environment variables (API key, etc.)
│
├── README.md                   # Main project README
├── QUICK_START.md              # Getting started guide
├── FAZE_SETUP_GUIDE.md         # FAZE API setup
├── INTEGRATION_GUIDE.md        # Integration documentation
├── LOG_EXPLORER_GUIDE.md       # Log exploration guide
└── requirements.txt            # Python dependencies
```

## Quick Reference

### 🎯 Main Usage

**Fetch all ART vulnerabilities with optional deduplication:**
```bash
cd agentic_red_team/
export FAZE_API_KEY="your-api-key"
export FAZE_DEDUP_VULNS="true"  # Optional: deduplicate by asset
python fetch_agentic_red_team_vulns.py
```

**Index to Splunk:**
```bash
export FAZE_API_KEY="your-api-key"
export FAZE_DEDUP_VULNS="true"
python splunk/addons/faze_security_addon.py
```

### 📁 By Use Case

| Task | Location | Command |
|------|----------|---------|
| Fetch all ART vulns | `agentic_red_team/` | `python fetch_agentic_red_team_vulns.py` |
| Fetch last 20 vulns | `agentic_red_team/` | `python fetch_agentic_red_team.py` |
| Test endpoint | `scripts/` | `python test_getart.py` |
| Send to Splunk | `splunk/addons/` | `python faze_security_addon.py` |
| Generate test data | `splunk/addons/` | `python agentic_red_team_input.py --count 100` |
| Explore logs | `splunk/utils/` | `python splunk_log_explorer.py` |

### ⚙️ Configuration

**Set environment variables** (create `config/.env`):
```bash
# Required
FAZE_API_KEY=your-api-key-here
FAZE_API_URL=https://api.faze.security

# Optional
FAZE_ART_ID=1000
FAZE_DEDUP_VULNS=true|false
```

See `splunk/config/ADDON_CONFIG.md` for Splunk-specific configuration.

### 📊 Output Files

- `output/all_assets.jsonl` — 121 FAZE assets (update with `fetch_agentic_red_team_vulns.py`)
- `output/agentic_red_team_vulns.jsonl` — 1,069 vulnerabilities (1,069 without dedup, 667 with dedup)

### 📚 Documentation

| Guide | Location | Topic |
|-------|----------|-------|
| Quick Start | `QUICK_START.md` | Getting started |
| ART Integration | `agentic_red_team/AGENTIC_RED_TEAM_GUIDE.md` | ART API details |
| Splunk Setup | `FAZE_SETUP_GUIDE.md` | Initial setup |
| Integration | `INTEGRATION_GUIDE.md` | End-to-end integration |
| Log Explorer | `LOG_EXPLORER_GUIDE.md` | Exploring fetched logs |
| Addon Config | `splunk/config/ADDON_CONFIG.md` | Splunk addon options |
| API Reference | `scripts/COMPREHENSIVE_API_GUIDE.md` | All API endpoints |

## Data Flow

```
FAZE API
   ↓
agentic_red_team/fetch_agentic_red_team_vulns.py
   ↓
output/*.jsonl (raw data)
   ↓
splunk/addons/faze_security_addon.py (with optional dedup)
   ↓
Splunk HEC / Splunk CLI
```

## Key Features

✅ **Deduplication Support** — Reduce duplicate vulns per asset  
✅ **Pagination** — Handles all 1,069 vulns across pages  
✅ **Asset Mapping** — Associates vulns with 121 assets by URL  
✅ **Splunk Ready** — JSONL format with sourcetype `faze:agentic_red_team`  
✅ **Error Handling** — SSL warnings suppressed, proper error reporting  
✅ **Environment Config** — API key and options via .env file
