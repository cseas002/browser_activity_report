# How the Browser Forensics Tool Works

## Overview

This tool works in three main steps:
1. **Extract** data from browsers
2. **Analyze** the data for suspicious patterns
3. **Report** findings in a timeline

## Step 1: Data Extraction

### What data does it get?
- **Browsing history** - websites visited, when, how many times
- **Downloads** - files downloaded, from where, when
- **Cookies** - small files websites store on your computer
- **Deleted data** - information users thought they deleted

### How does it extract data?

#### Chrome
- Reads SQLite database files from browser profile
- Files: `History`, `Cookies`, `Downloads`
- Converts timestamps from Chrome's format to normal dates

#### Firefox
- Reads SQLite databases: `places.sqlite`, `cookies.sqlite`
- **Special feature**: Can recover deleted history from session backups
- Uses LZ4 compression to decompress session files
- Looks for deleted data in unallocated database space

#### Safari (macOS only)
- Reads `History.db` and `Downloads.plist` files
- Looks for deleted records in "tombstone" tables
- Converts Safari's timestamp format

### Where does it look for data?

**Chrome locations:**
- Windows: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\`
- macOS: `~/Library/Application Support/Google/Chrome/Default/`
- Linux: `~/.config/google-chrome/Default/`

**Firefox locations:**
- Reads `profiles.ini` to find the right profile folder
- Looks in `~/.mozilla/firefox/` (Linux/macOS)
- Looks in `%APPDATA%\Mozilla\Firefox\Profiles\` (Windows)

**Safari locations:**
- macOS: `~/Library/Safari/`

## Step 2: Data Analysis

### Timeline Building
- Combines all browser data into one chronological timeline
- Groups activities into "sessions" (30-minute gaps = new session)
- Shows what happened when across all browsers

### Suspicious Activity Detection

#### Domain Analysis
- Checks if websites match known suspicious patterns
- Looks for keywords like "malware", "phishing", "tor"
- Flags IP addresses instead of normal domain names
- Identifies unusually long or weird domain names

#### Download Analysis
- Categorizes files by type (executables, documents, media)
- Flags downloads from suspicious websites
- Looks for files with suspicious names
- Detects "double extensions" like `document.pdf.exe`

#### Cookie Analysis
- Identifies tracking cookies from companies like Google Analytics
- Checks cookie security settings
- Counts third-party cookies

### Risk Scoring System

**High Risk (2+ points):**
- Dark web sites (.onion domains)
- Malware-related keywords
- Downloads from suspicious sources

**Medium Risk (1 point):**
- Phishing-related keywords
- Adult content sites
- Gambling sites
- IP addresses instead of domains

**Additional Risk Factors:**
- Unusually long domain names
- Suspicious keywords in filenames
- Double file extensions

## Step 3: Report Generation

### What gets included in reports?
- **Executive Summary** - Key findings at a glance
- **Timeline** - Chronological list of all activities
- **Suspicious Activity** - Flagged domains and downloads
- **Session Analysis** - When and how long users were active
- **Technical Details** - Raw data for investigators

### Report Formats
- **JSON** - Machine-readable data
- **CSV** - Spreadsheet-compatible timeline
- **HTML** - Visual charts and graphs
- **PDF** - Professional forensic report

## Technical Details

### Database Formats
- **SQLite** - Most browsers use this database format
- **Plist** - Safari uses Apple's property list format
- **Binary** - Some data is in binary format (harder to read)

### Timestamp Conversion
- **Chrome**: Microseconds since January 1, 1601
- **Firefox**: Microseconds since January 1, 1970 (Unix time)
- **Safari**: Seconds since January 1, 2001

### Data Recovery Techniques
- **Free Space Analysis** - Looks for deleted data in unused database space
- **Journal Files** - Checks for uncommitted transactions
- **Session Backups** - Firefox keeps compressed backups of recent sessions
- **Tombstone Records** - Safari marks deleted items instead of removing them

## Limitations

- **Permissions** - Needs access to browser profile folders
- **Encryption** - Can't read encrypted browser data
- **Cloud Sync** - Doesn't access cloud-synced data
- **Private Browsing** - Limited data from private/incognito mode
- **Platform Specific** - Some features only work on certain operating systems
