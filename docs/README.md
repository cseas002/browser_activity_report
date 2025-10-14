# Documentation

This folder contains detailed explanations of how the browser forensics tool works.

## Files

### [how-it-works.md](how-it-works.md)
Complete overview of the system:
- How data extraction works
- How analysis is performed
- How reports are generated
- Technical details and limitations

### [data-extraction.md](data-extraction.md)
Detailed explanation of data extraction:
- How each browser stores data
- Database formats and structures
- Extraction process step-by-step
- Advanced recovery techniques

### [analysis-process.md](analysis-process.md)
How the analysis works:
- Timeline construction
- Risk scoring algorithms
- Pattern detection methods
- Key findings generation

### [suspicious-patterns.md](suspicious-patterns.md)
What the tool considers suspicious:
- Domain risk patterns
- Download risk factors
- Behavioral indicators
- Risk level classifications

## Quick Reference

### Supported Browsers
- **Chrome/Chromium/Edge**: SQLite databases
- **Firefox**: SQLite + session backups (can recover deleted data)
- **Safari**: SQLite + plist files (macOS only)

### Risk Levels
- **HIGH (3+ points)**: Dark web, malware, data deletion attempts
- **MEDIUM (1-2 points)**: Phishing, adult content, high tracking
- **LOW (0-1 points)**: Normal browsing patterns

### Key Features
- **Timeline Reconstruction**: Chronological list of all activities
- **Deleted Data Recovery**: Finds data users thought they deleted
- **Suspicious Activity Detection**: Flags potentially dangerous websites and downloads
- **Cross-Browser Analysis**: Correlates activity across different browsers
- **Professional Reports**: Generates forensic reports in multiple formats

## For Investigators

This tool is designed for digital forensics investigations. It helps:
- Reconstruct user activity timelines
- Identify suspicious browsing patterns
- Recover deleted browser data
- Generate evidence for legal proceedings
- Understand user behavior patterns

## For Students

This tool demonstrates:
- How browsers store user data
- Digital forensics techniques
- Data recovery methods
- Pattern recognition algorithms
- Forensic report generation
