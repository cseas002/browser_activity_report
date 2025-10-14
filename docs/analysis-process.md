# How the Analysis Process Works

## Overview

After extracting data from browsers, the tool analyzes it to find patterns, suspicious activity, and create a timeline of user behavior.

## Analysis Steps

### Step 1: Timeline Construction
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

### Step 2: Domain Analysis
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

### Step 3: Download Analysis
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

### Step 4: Cookie Analysis
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

### Step 5: Risk Assessment
**Purpose**: Calculate risk scores and identify suspicious activity

**Risk Factors**:
- **Domain Risk**: Based on suspicious keywords and patterns
- **Download Risk**: Based on source and filename
- **Behavioral Risk**: Based on activity patterns
- **Privacy Risk**: Based on tracking cookie usage

## Risk Scoring Algorithm

### Domain Risk Scoring
```python
def assess_domain_risk(domain):
    risk_score = 0
    
    # High risk patterns (2 points each)
    if any(pattern in domain for pattern in ['malware', 'virus', 'trojan']):
        risk_score += 2
    
    # Medium risk patterns (1 point each)
    if any(pattern in domain for pattern in ['login', 'secure', 'account']):
        risk_score += 1
    
    # Additional factors (1 point each)
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        risk_score += 1  # IP address
    
    if len(domain) > 50:
        risk_score += 1  # Unusually long domain
    
    return risk_score
```

### Download Risk Scoring
```python
def assess_download_risk(url, filename):
    risk_score = 0
    
    # Source risk
    if is_suspicious_domain(url):
        risk_score += 2
    
    # Filename risk
    for keyword in suspicious_keywords:
        if keyword in filename.lower():
            risk_score += 1
    
    # Double extension risk
    if has_double_extension(filename):
        risk_score += 2
    
    return risk_score
```

## Pattern Detection

### Suspicious Domain Patterns
**High Risk (2 points)**:
- Dark web domains (`.onion`)
- Malware-related keywords
- Known malicious domains

**Medium Risk (1 point)**:
- Phishing-related keywords
- Adult content keywords
- Gambling-related keywords

**Additional Risk (1 point)**:
- IP addresses instead of domains
- Unusually long domain names
- Suspicious keywords in domain

### Suspicious Download Patterns
**High Risk**:
- Downloads from suspicious domains
- Executable files with suspicious names
- Double extensions (e.g., `document.pdf.exe`)

**Medium Risk**:
- Archive files from unknown sources
- Files with suspicious keywords in names
- Downloads from IP addresses

### Behavioral Patterns
**High Activity**:
- More than 100 browsing sessions
- Unusually long session durations
- Rapid succession of different domains

**Privacy Concerns**:
- More than 50 tracking cookies
- Extensive third-party cookie usage
- Known tracking domains

**Unusual Timing**:
- More than 30% activity during late night hours
- Very short or very long session durations
- Irregular activity patterns

## Key Findings Generation

### Finding Categories
**HIGH Severity**:
- Suspicious domain access
- Suspicious downloads
- Evidence of data deletion attempts

**MEDIUM Severity**:
- Privacy concerns (excessive tracking)
- High activity patterns
- Unusual timing patterns

**LOW Severity**:
- Late-night activity
- Unusual session patterns
- Minor privacy concerns

### Finding Structure
```python
finding = {
    'severity': 'HIGH|MEDIUM|LOW',
    'category': 'Suspicious Domain Access',
    'description': 'Found 5 potentially suspicious domains',
    'details': ['example1.com', 'example2.com']
}
```

## Data Correlation

### Cross-Browser Analysis
- Identifies same domains across different browsers
- Tracks user behavior patterns
- Detects attempts to hide activity

### Timeline Correlation
- Matches downloads with browsing history
- Correlates cookie creation with site visits
- Identifies related activities

### Session Analysis
- Groups activities into logical sessions
- Identifies session patterns
- Detects unusual session behavior

## Output Generation

### JSON Report
- Complete analysis results
- Risk scores and findings
- Detailed statistics
- Machine-readable format

### CSV Timeline
- Chronological event list
- All activities with timestamps
- Browser and activity type
- Human-readable format

### Session Data
- Session statistics
- Activity patterns
- Browser usage
- Timing analysis

## Quality Assurance

### Data Validation
- Check timestamp consistency
- Validate URL formats
- Verify risk score calculations
- Cross-check findings

### Error Handling
- Handle missing data gracefully
- Log analysis errors
- Provide fallback values
- Continue analysis despite errors

### Performance Optimization
- Process data in chunks
- Use efficient algorithms
- Minimize memory usage
- Optimize database queries
