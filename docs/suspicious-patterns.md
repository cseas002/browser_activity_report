# What the Tool Considers Suspicious

## Domain Patterns

### High Risk Domains (2 points each)
- **Dark Web**: Any `.onion` domain (Tor network)
- **Malware**: Domains containing:
  - `malware`
  - `virus` 
  - `trojan`
  - `ransomware`

### Medium Risk Domains (1 point each)
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

### Additional Risk Factors (1 point each)
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

## Download Patterns

### File Type Analysis
- **Executables** (`.exe`, `.msi`, `.dmg`, `.pkg`) - Potentially dangerous
- **Archives** (`.zip`, `.rar`, `.7z`) - Could contain malware
- **Documents** (`.pdf`, `.doc`, `.xls`) - Usually safe but can contain macros
- **Media** (`.jpg`, `.png`, `.mp4`) - Usually safe

### Suspicious Download Sources
- Downloads from any domain flagged as suspicious (see above)
- Downloads from IP addresses instead of domain names

### Suspicious Filenames
- Files containing suspicious keywords (same list as domains)
- **Double Extensions**: Files like `document.pdf.exe` (trying to hide executable)
- Files with multiple dots in suspicious combinations

### Download Risk Scoring
- **Source Risk**: +2 points for suspicious domain
- **Filename Risk**: +1 point per suspicious keyword
- **Double Extension**: +2 points for executable double extensions

## Behavioral Patterns

### High Activity Indicators
- **Too Many Sessions**: More than 100 browsing sessions (unusual for normal use)
- **Late Night Activity**: More than 30% of activity between 10 PM - 6 AM
- **Rapid Browsing**: Many different domains visited in short time

### Privacy Concerns
- **Excessive Tracking**: More than 50 tracking cookies detected
- **Third-Party Cookies**: High number of cookies from different domains
- **Known Tracking Domains**:
  - `google-analytics.com`
  - `doubleclick.net`
  - `facebook.com`
  - `googletagmanager.com`
  - `hotjar.com`
  - `mixpanel.com`

## Data Deletion Indicators

### Signs Someone Tried to Hide Activity
- **Journal Files Present**: Indicates recent database changes
- **Free Space in Databases**: May contain deleted records
- **Tombstone Records**: Safari marks deleted items instead of removing them
- **Session Backups**: Firefox keeps compressed backups of recent activity

### Recovery Status Levels
1. **Standard**: Normal browser data
2. **Session Backup**: Recovered from Firefox session files
3. **Tombstone**: Recovered from Safari deletion records
4. **Free Space**: Found in unallocated database space
5. **Journal**: Found in uncommitted transaction logs

## Risk Level Classifications

### HIGH Risk (Score 3+)
- Dark web access
- Malware-related domains
- Suspicious downloads with high scores
- Evidence of data deletion attempts

### MEDIUM Risk (Score 1-2)
- Phishing-related activity
- Adult content access
- Gambling sites
- High tracking cookie usage
- Unusual activity patterns

### LOW Risk (Score 0-1)
- Normal browsing patterns
- Legitimate websites
- Standard download behavior
- Minimal tracking

## Examples of Suspicious Activity

### Example 1: Malware Download
- **Domain**: `malware-samples.com`
- **Download**: `keygen.exe` from suspicious source
- **Risk Score**: 4 points (2 for domain + 1 for filename + 1 for executable)
- **Classification**: HIGH RISK

### Example 2: Phishing Attempt
- **Domain**: `secure-banking-login.com`
- **Activity**: Multiple visits to login pages
- **Risk Score**: 1 point (phishing keyword)
- **Classification**: MEDIUM RISK

### Example 3: Data Hiding
- **Activity**: Recent browsing history deleted
- **Evidence**: Journal files present, free space in database
- **Recovery**: Found deleted entries in session backups
- **Classification**: HIGH RISK (attempted data hiding)

### Example 4: Normal Activity
- **Domain**: `google.com`, `youtube.com`, `github.com`
- **Downloads**: PDF documents from legitimate sources
- **Risk Score**: 0 points
- **Classification**: LOW RISK
