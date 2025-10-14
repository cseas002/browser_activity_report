# Browser Forensics Tool - Complete Documentation

This document combines all documentation from the `documentation/methodology/` and `docs/` folders into a comprehensive guide.

## Table of Contents
1. [Overview](#overview)
2. [How It Works](#how-it-works)
3. [Data Extraction Process](#data-extraction-process)
4. [Analysis Process](#analysis-process)
5. [Suspicious Patterns](#suspicious-patterns)
6. [Forensic Methodology](#forensic-methodology)
7. [Firefox Deleted Data Recovery](#firefox-deleted-data-recovery)
8. [Report Generation](#report-generation)
9. [Technical Details](#technical-details)
10. [Limitations and Considerations](#limitations-and-considerations)

## Overview

This browser forensics tool works in three main steps:
1. **Extract** data from browsers
2. **Analyze** the data for suspicious patterns
3. **Report** findings in a timeline

### What data does it get?
- **Browsing history** - websites visited, when, how many times
- **Downloads** - files downloaded, from where, when
- **Cookies** - small files websites store on your computer
- **Deleted data** - information users thought they deleted

### Supported Browsers
- **Chrome/Chromium/Edge**: SQLite databases
- **Firefox**: SQLite + session backups (can recover deleted data)
- **Safari**: SQLite + plist files (macOS only)

### Key Features
- **Timeline Reconstruction**: Chronological list of all activities
- **Deleted Data Recovery**: Finds data users thought they deleted
- **Suspicious Activity Detection**: Flags potentially dangerous websites and downloads
- **Cross-Browser Analysis**: Correlates activity across different browsers
- **Professional Reports**: Generates forensic reports in multiple formats

## How It Works

### Step 1: Data Extraction

#### Chrome/Chromium
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

### Step 2: Data Analysis

#### Timeline Building
- Combines all browser data into one chronological timeline
- Groups activities into "sessions" (30-minute gaps = new session)
- Shows what happened when across all browsers

#### Suspicious Activity Detection

**Domain Analysis**
- Checks if websites match known suspicious patterns
- Looks for keywords like "malware", "phishing", "tor"
- Flags IP addresses instead of normal domain names
- Identifies unusually long or weird domain names

**Download Analysis**
- Categorizes files by type (executables, documents, media)
- Flags downloads from suspicious websites
- Looks for files with suspicious names
- Detects "double extensions" like `document.pdf.exe`

**Cookie Analysis**
- Identifies tracking cookies from companies like Google Analytics
- Checks cookie security settings
- Counts third-party cookies

### Step 3: Report Generation

**What gets included in reports?**
- **Executive Summary** - Key findings at a glance
- **Timeline** - Chronological list of all activities
- **Suspicious Activity** - Flagged domains and downloads
- **Session Analysis** - When and how long users were active
- **Technical Details** - Raw data for investigators

**Report Formats**
- **JSON** - Machine-readable data
- **CSV** - Spreadsheet-compatible timeline
- **HTML** - Visual charts and graphs
- **PDF** - Professional forensic report

## Data Extraction Process

### Browser Data Storage

#### Chrome/Chromium
**Database Format**: SQLite
**Key Files**:
- `History` - Browsing history and downloads
- `Cookies` - Cookie data
- `Login Data` - Saved passwords (not extracted for privacy)

**Data Structure**:
- `urls` table - Website URLs and titles
- `visits` table - When each URL was visited
- `downloads` table - Download records
- `cookies` table - Cookie information

#### Firefox
**Database Format**: SQLite + Compressed Session Files
**Key Files**:
- `places.sqlite` - Browsing history
- `cookies.sqlite` - Cookie data
- `sessionstore-backups/` - Compressed session backups

**Special Features**:
- Can recover deleted history from session backups
- Uses LZ4 compression for session files
- More forensic-friendly than Chrome

#### Safari (macOS only)
**Database Format**: SQLite + Property Lists
**Key Files**:
- `History.db` - Browsing history
- `Downloads.plist` - Download records
- `Cookies.binarycookies` - Cookie data (binary format)

**Special Features**:
- Uses "tombstone" records for deleted items
- Binary cookie format (harder to parse)
- Timestamps use different format

### Extraction Process

#### Step 1: Find Browser Profiles
The tool looks in standard locations for each browser:

**Chrome**:
- Windows: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\`
- macOS: `~/Library/Application Support/Google/Chrome/Default/`
- Linux: `~/.config/google-chrome/Default/`

**Firefox**:
- Reads `profiles.ini` to find active profile
- Looks in `~/.mozilla/firefox/` (Linux/macOS)
- Looks in `%APPDATA%\Mozilla\Firefox\Profiles\` (Windows)

**Safari**:
- macOS: `~/Library/Safari/`

#### Step 2: Copy Database Files
- Creates temporary copies to avoid locking issues
- Browser databases are often locked while browser is running
- Copies to `data/raw/` directory for analysis

#### Step 3: Parse Database Contents

**Chrome Extraction**
```sql
-- Example query for Chrome history
SELECT urls.url, urls.title, visits.visit_time
FROM urls
LEFT JOIN visits ON urls.id = visits.url
WHERE visits.visit_time IS NOT NULL
ORDER BY visits.visit_time DESC
```

**Firefox Extraction**
```sql
-- Example query for Firefox history
SELECT p.url, p.title, h.visit_date
FROM moz_places p
JOIN moz_historyvisits h ON p.id = h.place_id
WHERE h.visit_date IS NOT NULL
ORDER BY h.visit_date DESC
```

**Safari Extraction**
```sql
-- Example query for Safari history
SELECT url, visit_time
FROM history_items
LEFT JOIN history_visits ON history_items.id = history_visits.history_item
ORDER BY history_visits.visit_time DESC
```

#### Step 4: Convert Timestamps
Each browser uses different timestamp formats:

**Chrome**: Microseconds since January 1, 1601
```python
def chrome_timestamp_to_datetime(timestamp):
    base_date = datetime(1601, 1, 1)
    return base_date + timedelta(microseconds=timestamp)
```

**Firefox**: Microseconds since January 1, 1970 (Unix time)
```python
def firefox_timestamp_to_datetime(timestamp):
    return datetime.fromtimestamp(timestamp / 1000000)
```

**Safari**: Seconds since January 1, 2001
```python
def safari_timestamp_to_datetime(timestamp):
    base_date = datetime(2001, 1, 1)
    return base_date + timedelta(seconds=timestamp)
```

### Advanced Recovery Techniques

#### Firefox Session Recovery
1. **Find Session Files**: Look in `sessionstore-backups/` folder
2. **Decompress**: Use LZ4 decompression to read session data
3. **Parse JSON**: Extract URLs and titles from session data
4. **Filter**: Remove duplicates and invalid URLs

#### Safari Tombstone Analysis
1. **Check Tombstone Table**: Look for `history_tombstones` table
2. **Extract Deleted Records**: Get tombstone entries with timestamps
3. **Parse Binary Data**: Try to extract URLs from binary tombstone data
4. **Create Deleted Entries**: Mark as deleted with recovery status

#### Chrome Free Space Analysis
1. **Check Free Pages**: Count unallocated database pages
2. **Calculate Free Space**: Estimate how much deleted data might exist
3. **Create Summary**: Report potential recovery opportunities

## Analysis Process

### Timeline Construction
**Purpose**: Create a chronological list of all browser activities

**Process**:
1. Combine all browser data (history, downloads, cookies)
2. Sort by timestamp
3. Group related activities
4. Identify user sessions

**Session Detection**:
- New session starts if 30+ minutes gap between activities
- Tracks which browser was used
- Records domains visited and activity types

### Domain Analysis
**Purpose**: Identify which websites were visited and detect suspicious patterns

**Process**:
1. Extract domain names from URLs
2. Count visits per domain
3. Track first and last visit times
4. Identify cross-browser activity
5. Apply risk scoring

**Domain Processing**:
- Remove `www.` prefix for analysis
- Handle subdomains appropriately
- Group similar domains together

### Download Analysis
**Purpose**: Categorize downloads and identify potentially dangerous files

**Process**:
1. Categorize by file type (executables, documents, media, etc.)
2. Analyze download sources
3. Check filenames for suspicious patterns
4. Detect double extensions
5. Calculate risk scores

**File Type Categories**:
- **Executables**: `.exe`, `.msi`, `.dmg`, `.pkg` (potentially dangerous)
- **Archives**: `.zip`, `.rar`, `.7z` (could contain malware)
- **Documents**: `.pdf`, `.doc`, `.xls` (usually safe)
- **Media**: `.jpg`, `.png`, `.mp4` (usually safe)

### Cookie Analysis
**Purpose**: Understand tracking behavior and privacy concerns

**Process**:
1. Count total cookies
2. Identify secure vs insecure cookies
3. Find tracking domains
4. Analyze third-party cookies
5. Check cookie expiration times

**Tracking Domains**:
- `google-analytics.com`
- `doubleclick.net`
- `facebook.com`
- `googletagmanager.com`
- `hotjar.com`
- `mixpanel.com`

### Risk Assessment
**Purpose**: Calculate risk scores and identify suspicious activity

**Risk Factors**:
- **Domain Risk**: Based on suspicious keywords and patterns
- **Download Risk**: Based on source and filename
- **Behavioral Risk**: Based on activity patterns
- **Privacy Risk**: Based on tracking cookie usage

## Suspicious Patterns

### Domain Patterns

#### High Risk Domains (2 points each)
- **Dark Web**: Any `.onion` domain (Tor network)
- **Malware**: Domains containing:
  - `malware`
  - `virus` 
  - `trojan`
  - `ransomware`

#### Medium Risk Domains (1 point each)
- **Phishing**: Domains containing:
  - `login`
  - `secure`
  - `account`
  - `verify`
  - `banking`
- **Adult Content**: Domains containing:
  - `porn`
  - `sex`
  - `adult`
  - `xxx`
- **Gambling**: Domains containing:
  - `casino`
  - `betting`
  - `poker`
  - `lottery`

#### Additional Risk Factors (1 point each)
- **IP Addresses**: Using numbers instead of domain names (e.g., `192.168.1.1`)
- **Long Domains**: Domain names longer than 50 characters
- **Suspicious Keywords**: Any domain containing:
  - `password`
  - `admin`
  - `root`
  - `hack`
  - `exploit`
  - `crack`
  - `keygen`
  - `warez`
  - `torrent`
  - `pirate`

### Download Patterns

#### File Type Analysis
- **Executables** (`.exe`, `.msi`, `.dmg`, `.pkg`) - Potentially dangerous
- **Archives** (`.zip`, `.rar`, `.7z`) - Could contain malware
- **Documents** (`.pdf`, `.doc`, `.xls`) - Usually safe but can contain macros
- **Media** (`.jpg`, `.png`, `.mp4`) - Usually safe

#### Suspicious Download Sources
- Downloads from any domain flagged as suspicious (see above)
- Downloads from IP addresses instead of domain names

#### Suspicious Filenames
- Files containing suspicious keywords (same list as domains)
- **Double Extensions**: Files like `document.pdf.exe` (trying to hide executable)
- Files with multiple dots in suspicious combinations

### Risk Level Classifications

#### HIGH Risk (Score 3+)
- Dark web access
- Malware-related domains
- Suspicious downloads with high scores
- Evidence of data deletion attempts

#### MEDIUM Risk (Score 1-2)
- Phishing-related activity
- Adult content access
- Gambling sites
- High tracking cookie usage
- Unusual activity patterns

#### LOW Risk (Score 0-1)
- Normal browsing patterns
- Legitimate websites
- Standard download behavior
- Minimal tracking

## Forensic Methodology

### Phase 1: Planning and Preparation
**Objective**: Establish investigation scope, legal authority, and technical approach.

**Activities**:
- Define investigation objectives and scope
- Obtain legal authorization for data acquisition
- Identify target browsers and artifacts
- Prepare forensic workstation and tools
- Document chain of custody procedures

**Deliverables**:
- Investigation plan
- Legal authorization documentation
- Tool validation records
- Chain of custody forms

### Phase 2: Data Acquisition
**Objective**: Safely extract browser artifacts without modification.

**Principles**:
- Never modify original data
- Maintain forensic integrity
- Document all actions taken
- Preserve timestamps and metadata

**Acquisition Methods**:

#### Live System Acquisition
- Create memory images of running browsers
- Extract volatile data before system shutdown
- Capture network connections and cache state
- Document running processes and open files

#### Dead System Acquisition
- Create full disk images using write-blockers
- Hash verification of acquired data
- Preserve file system metadata
- Document hardware and acquisition details

#### Browser-Specific Acquisition
- Locate browser profile directories
- Copy database files safely to avoid locks
- Extract cache directories and temporary files
- Preserve file timestamps and permissions

### Phase 3: Data Analysis
**Objective**: Extract meaningful information from raw artifacts.

**Analysis Techniques**:

#### Timeline Construction
- Correlate timestamps across multiple data sources
- Convert browser-specific timestamps to standard format
- Identify chronological sequences of user actions
- Detect gaps or anomalies in activity

#### Pattern Analysis
- Domain access pattern identification
- Download behavior analysis
- Session pattern recognition
- Anomaly detection algorithms

#### Content Analysis
- URL categorization and classification
- Content type analysis
- Metadata extraction from downloads
- Keyword and pattern matching

#### Correlation Analysis
- Cross-browser activity correlation
- Multi-source data validation
- Session reconstruction
- User behavior pattern identification

### Phase 4: Artifact Classification
**Objective**: Categorize findings by forensic significance.

**Classification Categories**:

#### High Priority Artifacts
- Visits to known malicious domains
- Downloads of suspicious file types
- Unusual access patterns
- Evidence of data exfiltration

#### Medium Priority Artifacts
- Privacy-invasive tracking
- Unusual browsing hours
- High-volume data transfers
- Cross-browser inconsistencies

#### Low Priority Artifacts
- Normal browsing activity
- Legitimate downloads
- Standard tracking cookies
- Routine user behavior

## Firefox Deleted Data Recovery

### How Firefox Stores Data
Firefox is unique among browsers because it keeps multiple backups of user activity:

1. **Main Database** (`places.sqlite`) - Current browsing history
2. **Session Backups** (`sessionstore-backups/`) - Compressed backups of recent sessions
3. **WAL Files** (`places.sqlite-wal`) - Write-Ahead Logging for recent changes
4. **Journal Files** (`places.sqlite-journal`) - Transaction logs

### Recovery Methods

#### Method 1: Session File Recovery
**What it does**: Firefox automatically creates compressed backups of your browsing sessions
**How it works**:
1. Looks in `sessionstore-backups/` folder
2. Finds files like `recovery.jsonlz4`, `previous.jsonlz4`
3. Uses LZ4 decompression to read the data
4. Extracts URLs and titles from the JSON data
5. Filters out duplicates and invalid URLs

**Why it works**: Even when you "delete" history, Firefox keeps these session backups for crash recovery

#### Method 2: WAL File Recovery
**What it does**: Looks for recently deleted data in Write-Ahead Log files
**How it works**:
1. Checks for `places.sqlite-wal` file
2. Searches for URL patterns in the binary data
3. Extracts any URLs found in the WAL file
4. Marks them as "recovered from WAL"

**Why it works**: WAL files contain recent database changes before they're committed

#### Method 3: Database Free Space Analysis
**What it does**: Searches for deleted data in unallocated database space
**How it works**:
1. Reads the entire database as binary data
2. Uses pattern matching to find URL strings
3. Extracts surrounding text that might be page titles
4. Creates recovery entries for found data

**Why it works**: When data is deleted, it's not immediately overwritten - it's just marked as "free space"

#### Method 4: Cookie Analysis
**What it does**: Reconstructs visited sites from cookie data
**How it works**:
1. Reads all cookie hostnames
2. Reconstructs likely URLs from cookie domains
3. Creates entries for sites that had cookies but no history

**Why it works**: Cookies often outlast browsing history, especially for frequently visited sites

### Why Deleting More Shows Less
This is a key forensic principle:

1. **Normal deletion**: Records marked as deleted, space marked as 'free'
2. **Heavy deletion**: May trigger database VACUUM operation
3. **VACUUM**: Reorganizes database, overwrites free space
4. **Result**: Previously recoverable data is permanently destroyed

**💡 TIP**: For maximum recovery, analyze immediately after deletion!

## Report Generation

### Report Structure
1. **Executive Summary**: Key findings and conclusions
2. **Case Information**: Investigation details and scope
3. **Methodology**: Approach and techniques used
4. **Findings**: Detailed artifact analysis
5. **Timeline**: Chronological activity reconstruction
6. **Conclusions**: Investigative implications
7. **Appendices**: Detailed data and methodologies

### Evidence Documentation
- Chain of custody maintenance
- Tool validation records
- Hash verification documentation
- Analysis step documentation
- Finding source attribution

### Legal Considerations
- Admissible evidence requirements
- Expert witness preparation
- Report clarity for non-technical audiences
- Confidentiality and privacy protection

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

### Quality Assurance

#### Validation Procedures
- Tool accuracy verification
- Result cross-checking
- Peer review processes
- Documentation completeness

#### Error Prevention
- Double-check data extraction
- Verify timestamp conversions
- Validate correlation logic
- Document assumptions and limitations

#### Continuous Improvement
- Tool and method updates
- New artifact type identification
- Process optimization
- Training and skill development

## Limitations and Considerations

### Technical Limitations
- **Permissions** - Needs access to browser profile folders
- **Encryption** - Can't read encrypted browser data
- **Cloud Sync** - Doesn't access cloud-synced data
- **Private Browsing** - Limited data from private/incognito mode
- **Platform Specific** - Some features only work on certain operating systems

### Privacy Protection
- Minimize data collection scope
- Secure sensitive information
- Respect user privacy rights
- Follow data minimization principles

### Legal Compliance
- Adhere to search and seizure laws
- Maintain legal authorization
- Document all investigative actions
- Prepare for legal challenges

### Professional Standards
- Follow forensic best practices
- Maintain objectivity and impartiality
- Provide accurate and complete analysis
- Support findings with evidence

---

This comprehensive documentation provides everything needed to understand, use, and maintain the browser forensics tool while ensuring forensic integrity and legal compliance.
