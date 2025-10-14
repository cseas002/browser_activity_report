# How Data Extraction Works

## Overview

The tool extracts data from browser databases and files. Each browser stores data differently, so the tool needs to handle each one specially.

## Browser Data Storage

### Chrome/Chromium
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

### Firefox
**Database Format**: SQLite + Compressed Session Files
**Key Files**:
- `places.sqlite` - Browsing history
- `cookies.sqlite` - Cookie data
- `sessionstore-backups/` - Compressed session backups

**Special Features**:
- Can recover deleted history from session backups
- Uses LZ4 compression for session files
- More forensic-friendly than Chrome

### Safari (macOS only)
**Database Format**: SQLite + Property Lists
**Key Files**:
- `History.db` - Browsing history
- `Downloads.plist` - Download records
- `Cookies.binarycookies` - Cookie data (binary format)

**Special Features**:
- Uses "tombstone" records for deleted items
- Binary cookie format (harder to parse)
- Timestamps use different format

## Extraction Process

### Step 1: Find Browser Profiles
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

### Step 2: Copy Database Files
- Creates temporary copies to avoid locking issues
- Browser databases are often locked while browser is running
- Copies to `data/raw/` directory for analysis

### Step 3: Parse Database Contents

#### Chrome Extraction
```python
# Example query for Chrome history
SELECT urls.url, urls.title, visits.visit_time
FROM urls
LEFT JOIN visits ON urls.id = visits.url
WHERE visits.visit_time IS NOT NULL
ORDER BY visits.visit_time DESC
```

#### Firefox Extraction
```python
# Example query for Firefox history
SELECT p.url, p.title, h.visit_date
FROM moz_places p
JOIN moz_historyvisits h ON p.id = h.place_id
WHERE h.visit_date IS NOT NULL
ORDER BY h.visit_date DESC
```

#### Safari Extraction
```python
# Example query for Safari history
SELECT url, visit_time
FROM history_items
LEFT JOIN history_visits ON history_items.id = history_visits.history_item
ORDER BY history_visits.visit_time DESC
```

### Step 4: Convert Timestamps
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

## Advanced Recovery Techniques

### Firefox Session Recovery
1. **Find Session Files**: Look in `sessionstore-backups/` folder
2. **Decompress**: Use LZ4 decompression to read session data
3. **Parse JSON**: Extract URLs and titles from session data
4. **Filter**: Remove duplicates and invalid URLs

### Safari Tombstone Analysis
1. **Check Tombstone Table**: Look for `history_tombstones` table
2. **Extract Deleted Records**: Get tombstone entries with timestamps
3. **Parse Binary Data**: Try to extract URLs from binary tombstone data
4. **Create Deleted Entries**: Mark as deleted with recovery status

### Chrome Free Space Analysis
1. **Check Free Pages**: Count unallocated database pages
2. **Calculate Free Space**: Estimate how much deleted data might exist
3. **Create Summary**: Report potential recovery opportunities

## Data Validation

### Timestamp Validation
- Check if timestamps are reasonable (not in future, not too old)
- Handle different timezone issues
- Convert all to standard datetime format

### URL Validation
- Filter out invalid URLs (`about:`, `chrome://`, etc.)
- Remove duplicates across different data sources
- Validate URL format

### Data Integrity
- Check for missing required fields
- Handle database corruption gracefully
- Log extraction errors for debugging

## Output Format

### CSV Files
- `browser_history.csv` - All browsing history
- `browser_downloads.csv` - Download records
- `browser_cookies.csv` - Cookie data
- `deleted_browser_history.csv` - Recovered deleted data

### JSON Summary
- `extraction_summary.json` - Metadata about extraction
- Counts of records extracted
- List of browsers found
- Extraction timestamp

## Error Handling

### Common Issues
- **Permission Denied**: Browser files are protected
- **Database Locked**: Browser is running
- **Corrupted Database**: SQLite file is damaged
- **Missing Files**: Browser not installed or profile not found

### Solutions
- Request appropriate permissions
- Ask user to close browser
- Skip corrupted files and continue
- Provide helpful error messages

## Security Considerations

### Data Privacy
- Only extracts browsing data, not passwords
- Doesn't access encrypted data
- Respects user privacy settings where possible

### File Access
- Uses read-only access to database files
- Creates temporary copies instead of modifying originals
- Cleans up temporary files after extraction
