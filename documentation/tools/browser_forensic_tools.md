# Browser Forensic Analysis Tools

This document outlines the free and open-source tools used for extracting and analyzing browser artifacts in digital forensics investigations.

## Core Forensic Platforms

### Autopsy
**Description**: Open-source digital forensics platform with extensive browser artifact analysis capabilities.

**Key Features**:
- Automated extraction of browser artifacts
- Timeline analysis across multiple data sources
- Keyword search and filtering
- Report generation capabilities

**Installation**: Available for Windows, macOS, and Linux from [sleuthkit.org/autopsy](https://sleuthkit.org/autopsy/)

**Browser Support**:
- Chrome/Chromium (History, Downloads, Cookies, Cache)
- Firefox (places.sqlite, cookies.sqlite, cache2)
- Internet Explorer/Edge (index.dat, WebCacheV01.dat)
- Safari (History.db, Downloads.plist)

### Browser History Examiner (BHE)
**Description**: Specialized tool for extracting and analyzing web browser history from multiple browsers.

**Key Features**:
- Supports 20+ different browsers
- Extracts URLs, timestamps, visit counts
- Export to CSV/HTML reports
- Timeline visualization

**Installation**: Download from [magnetic-forensics.com](https://www.magnetic-forensics.com/products/browser-history-examiner/)

**Usage**:
```bash
# Command line usage for batch processing
BHE.exe -f "C:\Users\Username\AppData\Local\Google\Chrome\User Data\Default" -o output.csv
```

## Database Analysis Tools

### DB Browser for SQLite
**Description**: Visual tool for creating, designing, and editing SQLite database files.

**Key Features**:
- Browse database structure and contents
- Execute SQL queries
- Export data to CSV/JSON
- Import/export database schemas

**Installation**: Available at [sqlitebrowser.org](https://sqlitebrowser.org/)

**Browser Applications**:
- Chrome: History, Cookies, Login Data databases
- Firefox: places.sqlite, cookies.sqlite
- Safari: History.db

### SQLite Command Line Tool
**Description**: Command-line interface for SQLite databases included with SQLite.

**Usage Examples**:
```bash
# Query Chrome history
sqlite3 "History" "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 10;"

# Extract Firefox cookies
sqlite3 "cookies.sqlite" "SELECT host, name, value, expiry FROM moz_cookies WHERE host LIKE '%suspicious%';"
```

## Cache Analysis Tools

### Chrome Cache Extractor
**Description**: Tools for extracting and analyzing Chrome's cache files.

**Key Features**:
- Extract cached web content
- Analyze cache metadata
- Reconstruct web pages from cache

**Manual Extraction**:
```bash
# Chrome cache is stored in data_# files
# Use tools like chrome_cache_extractor.py
python chrome_cache_extractor.py -d "/path/to/cache" -o extracted_files/
```

### Browser Cache Analysis Scripts
Custom Python scripts using libraries like:
- `browserhistory` - Python library for browser history extraction
- `sqlite3` - Built-in SQLite database access
- `os` - File system operations

## Network Analysis Tools

### Wireshark
**Description**: Network protocol analyzer for capturing and examining network traffic.

**Browser Applications**:
- Analyze HTTP/HTTPS traffic patterns
- Extract URLs from network captures
- Identify download activities
- Detect proxy usage

**Installation**: Available at [wireshark.org](https://www.wireshark.org/)

**Filters for Browser Analysis**:
```
http.request.uri contains "suspicious"
http.cookie contains "session"
tcp.port == 80 or tcp.port == 443
```

## Metadata Analysis Tools

### ExifTool
**Description**: Platform-independent Perl library for reading and writing meta information in files.

**Browser Applications**:
- Extract metadata from downloaded files
- Analyze file timestamps and origins
- Identify file sources and modifications

**Usage**:
```bash
# Extract metadata from downloaded file
exiftool -a -u -g1 downloaded_file.exe

# Recursive analysis of download directory
exiftool -r -csv downloads/ > metadata_report.csv
```

## File System Analysis Tools

### The Sleuth Kit (TSK)
**Description**: Collection of command-line tools for forensic analysis of disk images.

**Key Tools**:
- `fls`: File listing
- `icat`: File content extraction
- `fsstat`: File system statistics
- `tsk_recover`: File recovery

**Usage for Browser Analysis**:
```bash
# List files in browser profile directory
fls -r disk_image.dd | grep "Chrome"

# Extract browser database
icat disk_image.dd inode_number > history.sqlite
```

## Custom Analysis Scripts

### Python Libraries for Browser Forensics
```python
import sqlite3
import os
import json
import csv
from datetime import datetime
import browserhistory as bh  # Third-party library
```

### Key Python Scripts Developed:
1. **browser_extractor.py**: Automated extraction from multiple browsers
2. **timeline_builder.py**: Correlates timestamps across data sources
3. **artifact_analyzer.py**: Identifies suspicious patterns
4. **report_generator.py**: Creates forensic reports

## Tool Installation and Setup

### Windows Environment
```batch
# Install Python and required libraries
pip install browserhistory sqlite3 pandas matplotlib

# Download and install Autopsy
# Download Browser History Examiner
# Install ExifTool
```

### macOS/Linux Environment
```bash
# Install dependencies
brew install python sqlite exiftool wireshark

# Install Python libraries
pip install browserhistory pandas matplotlib

# Install Autopsy (via package manager or direct download)
```

## Tool Validation and Testing

### Test Data Sources
- Use browser test profiles with known activity
- Create controlled test scenarios
- Validate tool outputs against known data
- Cross-reference results between tools

### Chain of Custody
- Document tool versions used
- Preserve original evidence files
- Log all analysis steps
- Maintain audit trails

## Best Practices

1. **Tool Selection**: Choose tools based on specific browser artifacts needed
2. **Version Consistency**: Document tool versions for reproducibility
3. **Validation**: Always validate tool outputs against known data
4. **Documentation**: Record all steps and findings
5. **Legal Compliance**: Follow forensic acquisition procedures

## Troubleshooting Common Issues

### Database Locked Errors
- Ensure browser is closed before acquisition
- Copy database files instead of working on originals
- Use read-only access for analysis

### Timestamp Conversion
- Chrome: WebKit timestamp (microseconds since 1601-01-01)
- Firefox: PRTime (microseconds since 1970-01-01)
- Safari: Mac absolute time (seconds since 2001-01-01)

### Cache File Corruption
- Use multiple extraction attempts
- Cross-reference with other data sources
- Document any corruption encountered
