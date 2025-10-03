# Browser Activity Forensic Analysis Project

## Project Overview

This project demonstrates digital forensic analysis of web browser artifacts to reconstruct user activity patterns. By examining browser data such as browsing history, cookies, cached files, and download records, we can identify user behavior, detect visits to suspicious sites, and provide evidence that persists even after deletion attempts.

## Objectives

- **Extract Browser Artifacts**: Collect browsing history, cookies, cache, and download records using forensic tools
- **Timeline Reconstruction**: Build chronological timeline of user actions from multiple data sources
- **Persistence Analysis**: Demonstrate that browser traces remain despite user deletion attempts
- **Incident Report**: Generate professional forensic reports documenting findings
- **Educational Value**: Show practical applications of browser forensics in investigations

## Project Structure

```
browser_activity_report/
├── tools/                 # Forensic tools and scripts
├── scripts/              # Analysis and extraction scripts
├── data/
│   ├── raw/             # Raw extracted browser data
│   └── processed/       # Analyzed and processed data
├── reports/             # Generated forensic reports
├── documentation/
│   ├── tools/          # Tool documentation and usage
│   └── methodology/    # Forensic methodology guides
├── README.md           # This file
└── LICENSE
```

## Quick Start

### 1. Setup Environment
```bash
# Make setup script executable and run it
chmod +x scripts/setup_environment.sh
./scripts/setup_environment.sh
```

This script will:
- **Detect your Python environment** (Anaconda/conda or system Python)
- **Create a virtual environment** (if not using Anaconda)
- **Install required Python packages** (pandas, matplotlib, etc.)
- **Set up system tools** (SQLite, ExifTool)
- **Create necessary directories**
- **Verify the installation**

**Important**: After setup, you must activate the environment before running scripts:

**If using Anaconda:**
```bash
conda activate your_env_name  # Use your Anaconda environment name
```

**If using virtual environment:**
```bash
source browser_forensics_env/bin/activate
```

### 2. Extract Browser Data
```bash
# Extract browser artifacts from default locations
python scripts/browser_extractor.py

# Extract from specific browsers or custom paths
python scripts/browser_extractor.py -b chrome firefox
python scripts/browser_extractor.py -p chrome:/path/to/chrome/profile
```

**What gets extracted:**
- Browsing history (URLs, titles, timestamps)
- Download records (files, sources, times)
- Cookie data (sessions, tracking info)
- Data saved to `data/raw/` directory

### 3. Analyze Extracted Data
```bash
# Run forensic analysis on extracted data
python scripts/analyze_artifacts.py

# Specify custom input/output directories
python scripts/analyze_artifacts.py -i data/raw -o data/processed
```

**Analysis includes:**
- Timeline reconstruction
- Suspicious domain detection
- Download pattern analysis
- Session identification
- Risk assessment

### 4. Generate Forensic Report
```bash
# Create comprehensive incident report
python scripts/generate_report.py

# Customize report details
python scripts/generate_report.py -c "CASE-2025-001" -i "John Doe"
```

**Report features:**
- Executive summary
- Detailed findings
- Activity timeline
- Technical analysis
- Forensic conclusions

## Detailed Usage Guide

### Browser Data Extraction

First, activate your environment:

```bash
# Anaconda users:
conda activate your_env_name

# Virtual environment users:
source browser_forensics_env/bin/activate
```

Then run the extraction script:

```bash
# View all options
python scripts/browser_extractor.py --help

# Extract from all detected browsers
python scripts/browser_extractor.py

# Extract only from Chrome and Firefox
python scripts/browser_extractor.py -b chrome firefox

# Use custom profile paths
python scripts/browser_extractor.py -p chrome:/custom/path firefox:/home/user/.mozilla

# Save to custom output directory
python scripts/browser_extractor.py -o /path/to/output
```

**Supported Browsers:**
- Google Chrome/Chromium
- Mozilla Firefox
- Apple Safari (macOS only)
- Microsoft Edge

### Forensic Analysis

First, activate your environment:

```bash
# Anaconda users:
conda activate your_env_name

# Virtual environment users:
source browser_forensics_env/bin/activate
```

Then run the analysis script:

```bash
# Basic analysis
python scripts/analyze_artifacts.py

# Advanced options
python scripts/analyze_artifacts.py --help

# Custom directories
python scripts/analyze_artifacts.py -i data/raw -o data/processed
```

**Analysis Outputs:**
- `forensic_analysis_report.json` - Complete analysis results
- `timeline_events.csv` - Chronological event timeline
- `user_sessions.json` - Session analysis data

### Report Generation

First, activate your environment:

```bash
# Anaconda users:
conda activate your_env_name

# Virtual environment users:
source browser_forensics_env/bin/activate
```

Then generate reports:

```bash
# Basic report
python scripts/generate_report.py

# Custom case details
python scripts/generate_report.py \
  -c "BF-2025-001" \
  -i "Digital Forensics Team" \
  -f "monthly_browser_report.txt"

# Custom directories
python scripts/generate_report.py -a data/processed -o reports/
```

## Data Flow

```
Browser Profiles → Extraction → Raw Data → Analysis → Processed Data → Report
     ↓              ↓          ↓           ↓           ↓              ↓
   Chrome/       browser_    .csv       analyze_    .json/         .txt
   Firefox/     extractor   files      artifacts    .csv         report
   Safari       .py         ↓           .py          ↓              ↓
   Edge                    data/raw   data/processed reports/
```

## Output Files

### Raw Data (`data/raw/`)
- `browser_history.csv` - All browsing history records
- `browser_downloads.csv` - Download activity records
- `browser_cookies.csv` - Cookie data
- `extraction_summary.json` - Extraction metadata

### Processed Data (`data/processed/`)
- `forensic_analysis_report.json` - Complete analysis results
- `timeline_events.csv` - Chronological timeline
- `user_sessions.json` - Session analysis

### Reports (`reports/`)
- `browser_forensics_report_[timestamp].txt` - Full incident report

## Forensic Tools Used

### Core Forensic Platforms
- **Custom Python Scripts**: Tailored extraction and analysis
- **SQLite Browser**: Database inspection (manual)
- **Timeline Analysis**: Chronological event reconstruction
- **Pattern Matching**: Suspicious activity detection

### Browser-Specific Analysis
- **Chrome/Chromium**: SQLite databases, cache analysis
- **Firefox**: places.sqlite, cookies.sqlite parsing
- **Safari**: History.db, Cookies.binarycookies
- **Edge**: Similar to Chrome/Chromium structure

## Data Sources Analyzed

1. **Browsing History**: URLs visited, timestamps, visit counts
2. **Cookies**: Session data, tracking information, authentication tokens
3. **Cache Files**: Temporary web content, images, scripts
4. **Download Records**: File downloads, sources, timestamps
5. **Bookmarks**: Saved pages and user interests
6. **Form Data**: Autocomplete data and form submissions
7. **Extensions**: Installed browser extensions and their data

## Methodology

### Phase 1: Data Acquisition
- Image test machine drives
- Extract browser profile directories
- Preserve chain of custody
- Document acquisition process

### Phase 2: Artifact Extraction
- Parse browser databases (SQLite)
- Extract cache contents
- Analyze cookie stores
- Process download histories

### Phase 3: Timeline Analysis
- Correlate timestamps across data sources
- Identify user behavior patterns
- Detect suspicious activities
- Reconstruct user sessions

### Phase 4: Report Generation
- Create chronological timeline
- Document findings with evidence
- Provide investigative conclusions
- Include technical appendices

## Legal and Ethical Considerations

- All analysis performed on test machines only
- Data handling follows digital forensics best practices
- No real user data used without explicit consent
- Educational purposes only

## Expected Outcomes

- Comprehensive browser activity timeline
- Identification of persistent artifacts
- Demonstration of forensic reconstruction capabilities
- Professional incident-style report
- Educational insights into browser forensics

## References

- NIST Digital Forensics Guidelines
- Browser Forensics literature
- Digital Evidence best practices
- Forensic tool documentation

---

**Course**: EP2780 Digital Forensics
**Institution**: KTH Royal Institute of Technology


