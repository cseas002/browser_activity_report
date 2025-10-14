# Browser Activity Forensic Analysis

## What is this?

This is a digital forensics tool that analyzes web browser data to find out what someone was doing online. It looks at browsing history, downloads, and cookies to create a timeline of activities and detect suspicious behavior.

## What does it do?

- **Extracts** browser data (history, downloads, cookies)
- **Finds** deleted data that users thought they removed
- **Detects** suspicious websites and downloads
- **Creates** a timeline of all online activities
- **Generates** forensic reports for investigations

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

## How to use it

### 1. Setup
```bash
# Run the setup script
chmod +x scripts/setup.sh
./scripts/setup.sh

# Activate the environment
source .venv/bin/activate
```

### 2. Extract data from browsers
```bash
python scripts/browser_extractor.py
```

### 3. Analyze the data
```bash
python scripts/analyze_artifacts.py
```

### 4. Generate report
```bash
python scripts/generate_report.py
```

## How it works

1. **Extract**: Gets data from Chrome, Firefox, Safari browsers
2. **Analyze**: Looks for suspicious patterns and deleted data
3. **Report**: Creates a timeline and forensic report

## Supported Browsers
- Chrome/Chromium
- Firefox  
- Safari (macOS only)

## What it finds

- **Suspicious websites** (malware, phishing, dark web)
- **Deleted browsing history** that users thought was gone (only on Firefox - Linux)
- **Download patterns** and potentially dangerous files
- **User activity timeline** showing when and what they did online
- **Tracking cookies** and privacy concerns

---

**Course**: EP2780 Digital Forensics  
**Institution**: KTH Royal Institute of Technology


