# Firefox Forensics Tools

This directory contains specialized tools for Firefox browser forensics, focusing on history recovery and analysis.

## Tools Overview

1. **firefox_forensics.sh**: Bash script that orchestrates various Firefox forensic tools
   - Finds Firefox profiles
   - Extracts session data
   - Analyzes places.sqlite database
   - Integrates with dumpzilla

2. **firefox_forensics.py**: Python wrapper for forensic tools
   - Provides programmatic access to forensic tools
   - Combines results from multiple recovery methods
   - Handles data parsing and formatting

3. **dumpzilla**: Third-party tool for comprehensive Firefox data extraction
   - Extracts history, downloads, bookmarks
   - Recovers cache and preferences
   - Provides detailed JSON output

## Prerequisites

```bash
# Install required system packages
sudo apt install -y cargo mozlz4-tools sqlite3 python3

# Install firefed (optional but recommended)
cargo install firefed
```

## Usage

### Using the Bash Script

```bash
# Run the forensics script
./firefox_forensics.sh
```

The script will:
- Automatically find Firefox profiles
- Extract and analyze data
- Save results in the `output` directory

### Using the Python Module

```python
from firefox_forensics import FirefoxForensics

# Initialize with a specific profile
forensics = FirefoxForensics("/path/to/firefox/profile")

# Get all deleted history
deleted_history = forensics.get_all_deleted_history()

# Run specific analysis
places_analysis = forensics.analyze_places_database()
session_data = forensics.parse_session_data()
dumpzilla_data = forensics.run_dumpzilla()
```

## Output Files

The tools generate several output files in the `output` directory:

- `deleted_history.json`: Combined results from all recovery methods
- `places_dump.sql`: SQLite database dump for manual analysis
- `dumpzilla_output.json`: Raw output from dumpzilla
- Various `.json` files from session recovery

## Recovery Methods

1. **SQLite Analysis**
   - Analyzes free pages in places.sqlite
   - Checks Write-Ahead Log (WAL) for recent deletions
   - Recovers partially overwritten records

2. **Session Recovery**
   - Extracts URLs from session backup files
   - Recovers data from compressed LZ4 files
   - Analyzes previous sessions

3. **Dumpzilla Analysis**
   - Comprehensive data extraction
   - Cache analysis
   - Preference recovery

## Limitations

- Some data may be unrecoverable if securely deleted
- Encrypted profiles require additional handling
- Success rate depends on Firefox version and system activity
- Some features require root access

## Contributing

Feel free to submit issues and enhancement requests!
