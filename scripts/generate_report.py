#!/usr/bin/env python3
"""
Browser Forensics Incident Report Generator

This script generates professional incident-style forensic reports
based on browser artifact analysis, reconstructing user activity
timelines and documenting findings.

Author: Browser Forensics Project
Date: October 2025
"""

import os
import json
import csv
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

class ForensicReportGenerator:
    """Class for generating forensic reports."""

    def __init__(self, analysis_dir="../data/processed", output_dir="../reports"):
        self.analysis_dir = Path(analysis_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Load analysis data
        self.load_analysis_data()

    def load_analysis_data(self):
        """Load processed analysis data."""
        try:
            with open(self.analysis_dir / 'forensic_analysis_report.json', 'r', encoding='utf-8') as f:
                self.report_data = json.load(f)
        except FileNotFoundError:
            print("Error: Analysis report not found. Run analyze_artifacts.py first.")
            self.report_data = None

        try:
            with open(self.analysis_dir / 'user_sessions.json', 'r', encoding='utf-8') as f:
                self.session_data = json.load(f)
        except FileNotFoundError:
            self.session_data = None

        # Load timeline data
        self.timeline_data = []
        timeline_file = self.analysis_dir / 'timeline_events.csv'
        if timeline_file.exists():
            with open(timeline_file, 'r', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    if row.get('timestamp'):
                        try:
                            row['timestamp'] = datetime.fromisoformat(row['timestamp'])
                        except ValueError:
                            pass
                    self.timeline_data.append(row)

    def generate_incident_report(self, case_number="BF-2025-001", investigator="Browser Forensics Team"):
        """Generate comprehensive incident report."""

        if not self.report_data:
            return None

        report_content = []

        # Report Header
        report_content.append(self.generate_report_header(case_number, investigator))

        # Executive Summary
        report_content.append(self.generate_executive_summary())

        # Case Information
        report_content.append(self.generate_case_information(case_number, investigator))

        # Methodology
        report_content.append(self.generate_methodology())

        # Findings
        report_content.append(self.generate_findings())

        # Timeline Analysis
        report_content.append(self.generate_timeline_section())

        # Session Analysis
        report_content.append(self.generate_session_analysis())

        # Technical Details
        report_content.append(self.generate_technical_details())

        # Conclusions
        report_content.append(self.generate_conclusions())

        # Appendices
        report_content.append(self.generate_appendices())

        return "\n\n".join(report_content)

    def generate_report_header(self, case_number, investigator):
        """Generate report header."""
        header = f"""
BROWSER FORENSICS INCIDENT REPORT
{'='*50}

Case Number: {case_number}
Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Investigator: {investigator}
Analysis Tool: Browser Forensics Analysis Suite v1.0

CONFIDENTIAL - FOR OFFICIAL USE ONLY
"""
        return header

    def generate_executive_summary(self):
        """Generate executive summary."""
        summary = self.report_data.get('summary', {})

        summary_text = f"""
EXECUTIVE SUMMARY
{'='*20}

This report presents the findings of a digital forensic analysis of browser artifacts
extracted from a test machine. The analysis focused on reconstructing user activity
patterns, identifying suspicious behaviors, and demonstrating the persistence of
browser data despite deletion attempts.

KEY METRICS:
- Total browsing history records analyzed: {summary.get('total_history_records', 0):,}
- Total download records examined: {summary.get('total_download_records', 0):,}
- Total cookie records reviewed: {summary.get('total_cookie_records', 0):,}
- Unique domains accessed: {summary.get('unique_domains', 0):,}
- User sessions identified: {summary.get('user_sessions', 0):,}
- Suspicious domains detected: {summary.get('suspicious_domains', 0)}
- Suspicious downloads identified: {summary.get('suspicious_downloads', 0)}

The analysis revealed persistent browser artifacts that survive user deletion
attempts, demonstrating the forensic value of browser data in reconstructing
user activity and identifying potentially malicious behavior.
"""
        return summary_text

    def generate_case_information(self, case_number, investigator):
        """Generate case information section."""
        case_info = f"""
CASE INFORMATION
{'='*20}

Case Number: {case_number}
Investigation Type: Browser Artifact Analysis
Date of Analysis: {datetime.now().strftime('%Y-%m-%d')}
Lead Investigator: {investigator}
Analysis Location: KTH Royal Institute of Technology

PURPOSE:
This investigation was conducted as part of an educational digital forensics
project to analyze web browser artifacts and demonstrate their value in
reconstructing user activity patterns, even after attempted data deletion.

SCOPE:
- Extraction of browser history from multiple browsers
- Analysis of download records and file transfers
- Examination of cookie data and session management
- Timeline reconstruction of user activities
- Identification of suspicious or potentially malicious behavior
"""
        return case_info

    def generate_methodology(self):
        """Generate methodology section."""
        methodology = """
METHODOLOGY
{'='*15}

DATA ACQUISITION:
Browser artifacts were extracted using custom Python scripts designed to
access browser databases safely without modifying original files. The
extraction process included:

1. Identification of browser profile locations
2. Safe copying of database files to prevent locking issues
3. Parsing of SQLite databases containing browser data
4. Timestamp conversion from browser-specific formats to standard datetime
5. Correlation of data across multiple browsers and data sources

ANALYSIS TECHNIQUES:
- Chronological timeline construction from multiple data sources
- Domain pattern analysis for suspicious activity detection
- Download pattern analysis for malware indicators
- Cookie analysis for tracking and session management
- Session analysis for user behavior patterns
- Risk assessment using predefined suspicious indicators

TOOLS UTILIZED:
- Custom Python extraction scripts (browser_extractor.py)
- SQLite database analysis libraries
- Timeline correlation algorithms
- Pattern matching and risk assessment algorithms

DATA INTEGRITY:
All original browser files were preserved and never modified. Analysis was
performed on copies of the data to maintain forensic integrity and chain
of custody principles.
"""
        return methodology

    def generate_findings(self):
        """Generate findings section."""
        findings = """
FINDINGS
{'='*10}

BROWSER ACTIVITY OVERVIEW:
"""

        summary = self.report_data.get('summary', {})
        findings += f"""
The analysis revealed extensive browser activity with {summary.get('total_history_records', 0):,} page visits
across {summary.get('unique_domains', 0):,} unique domains. The user engaged in {summary.get('user_sessions', 0):,}
browsing sessions over the analysis period.

SUSPECT DOMAINS:
{len(self.report_data.get('domain_analysis', {}).get('suspicious_domains', {}))} potentially suspicious domains
were identified based on pattern matching against known malicious indicators.
"""

        suspicious_domains = self.report_data.get('domain_analysis', {}).get('suspicious_domains', {})
        if suspicious_domains:
            findings += "\nTop Suspicious Domains:\n"
            for i, (domain, data) in enumerate(list(suspicious_domains.items())[:5], 1):
                stats = data.get('stats', {})
                findings += f"{i}. {domain} (Risk Level: {data.get('risk_level', 0)})\n"
                findings += f"   - Visits: {stats.get('visits', 0)}\n"
                findings += f"   - First Visit: {stats.get('first_visit', 'Unknown')}\n"
                findings += f"   - Browsers: {', '.join(stats.get('browsers', []))}\n"
                findings += f"   - Risk Factors: {', '.join(data.get('risk_factors', []))}\n\n"

        findings += f"""
DOWNLOAD ACTIVITY:
{summary.get('total_download_records', 0):,} download events were analyzed, with
{len(self.report_data.get('download_analysis', {}).get('suspicious_downloads', []))} flagged as potentially suspicious.
"""

        suspicious_downloads = self.report_data.get('download_analysis', {}).get('suspicious_downloads', [])
        if suspicious_downloads:
            findings += "\nSuspicious Downloads:\n"
            for i, download in enumerate(suspicious_downloads[:5], 1):
                findings += f"{i}. {download.get('target_path', 'Unknown file')}\n"
                findings += f"   - Source: {download.get('url', 'Unknown')}\n"
                findings += f"   - Browser: {download.get('browser', 'Unknown')}\n"
                findings += f"   - Risk Score: {download.get('risk_score', 0)}\n"
                findings += f"   - Risk Factors: {', '.join(download.get('risk_factors', []))}\n\n"

        findings += """
COOKIE ANALYSIS:
Cookie data revealed extensive tracking and session management activity.
"""

        cookie_analysis = self.report_data.get('cookie_analysis', {})
        findings += f"""
- Total cookies: {cookie_analysis.get('total_cookies', 0):,}
- Secure cookies: {cookie_analysis.get('secure_cookies', 0):,}
- Third-party cookies: {cookie_analysis.get('third_party_cookies', 0):,}
- Tracking domains detected: {len(cookie_analysis.get('tracking_domains', {}))}
"""

        # Key findings
        key_findings = self.report_data.get('key_findings', [])
        if key_findings:
            findings += "\nKEY FORENSIC FINDINGS:\n"
            for finding in key_findings:
                findings += f"\n{finding.get('severity', 'UNKNOWN')} SEVERITY: {finding.get('category', 'Unknown')}\n"
                findings += f"Description: {finding.get('description', '')}\n"
                if finding.get('details'):
                    findings += f"Details: {finding.get('details')}\n"

        return findings

    def generate_timeline_section(self):
        """Generate timeline analysis section."""
        timeline_section = """
TIMELINE ANALYSIS
{'='*20}

The following timeline reconstructs user activity based on correlated browser artifacts:
"""

        # Group timeline events by date
        events_by_date = defaultdict(list)
        for event in self.timeline_data[:100]:  # Limit to first 100 events for readability
            if event.get('timestamp'):
                date_key = event['timestamp'].strftime('%Y-%m-%d')
                events_by_date[date_key].append(event)

        for date in sorted(events_by_date.keys(), reverse=True):
            timeline_section += f"\n{date}:\n"
            day_events = sorted(events_by_date[date], key=lambda x: x.get('timestamp') or datetime.min)

            for event in day_events[:20]:  # Limit events per day
                time_str = event.get('timestamp').strftime('%H:%M:%S') if event.get('timestamp') else 'Unknown'
                event_type = event.get('type', 'unknown').replace('_', ' ').title()
                browser = event.get('browser', 'Unknown')
                details = event.get('details', '')

                timeline_section += f"  {time_str} [{browser}] {event_type}: {details[:100]}{'...' if len(details) > 100 else ''}\n"

        timeline_section += f"\n[Note: Showing first 100 events of {len(self.timeline_data)} total events]"
        return timeline_section

    def generate_session_analysis(self):
        """Generate session analysis section."""
        if not self.session_data:
            return "\nSESSION ANALYSIS\n{'='*20}\n\nSession data not available."

        session_stats = self.session_data.get('session_stats', {})
        sessions = self.session_data.get('sessions', [])

        session_section = f"""
SESSION ANALYSIS
{'='*20}

User browsing behavior was analyzed to identify distinct sessions based on activity patterns.

SESSION STATISTICS:
- Total sessions identified: {session_stats.get('total_sessions', 0):,}
- Average session duration: {session_stats.get('avg_session_duration', 'Unknown')}
- Total events across all sessions: {session_stats.get('total_events', 0):,}
- Browsers used: {', '.join(session_stats.get('browsers_used', []))}

PEAK ACTIVITY HOURS:
"""

        peak_hours = session_stats.get('peak_activity_hours', {})
        for hour in range(24):
            count = peak_hours.get(str(hour), 0)
            if count > 0:
                am_pm = "AM" if hour < 12 else "PM"
                display_hour = hour if hour <= 12 else hour - 12
                if display_hour == 0:
                    display_hour = 12
                session_section += f"{display_hour:2d} {am_pm}: {'█' * min(count, 20)} ({count})\n"

        session_section += f"\nTOP SESSIONS BY ACTIVITY:\n"
        sorted_sessions = sorted(sessions, key=lambda x: x.get('events_count', 0), reverse=True)
        for i, session in enumerate(sorted_sessions[:5], 1):
            start_time = session.get('start_time', 'Unknown')
            duration = session.get('duration', 'Unknown')
            events_count = session.get('events_count', 0)
            browsers = ', '.join(session.get('browsers', []))
            domains = len(session.get('domains', []))

            session_section += f"{i}. Session starting {start_time}\n"
            session_section += f"   Duration: {duration} | Events: {events_count} | Browsers: {browsers} | Domains: {domains}\n"

        return session_section

    def generate_technical_details(self):
        """Generate technical details section."""
        technical_details = """
TECHNICAL DETAILS
{'='*20}

BROWSER DATA STRUCTURES ANALYZED:

CHROME/CHROMIUM BROWSERS:
- History Database: WebKit timestamps (microseconds since 1601-01-01)
- Cookies Database: Encrypted storage with metadata
- Downloads Database: File transfer records with source URLs
- Cache: Binary data blocks with metadata headers

FIREFOX BROWSER:
- places.sqlite: PRTime timestamps (microseconds since 1970-01-01)
- cookies.sqlite: Cookie storage with expiration data
- Cache: File-based storage with index files

SAFARI BROWSER:
- History.db: Mac absolute time (seconds since 2001-01-01)
- Cookies.binarycookies: Binary plist format
- Downloads.plist: Property list format

DATA EXTRACTION METHODS:
- SQLite database parsing with safe copying to avoid locks
- Timestamp conversion algorithms for each browser format
- Binary data structure parsing for Safari cookies
- Metadata extraction from cached files

ANALYSIS ALGORITHMS:
- Timeline correlation across multiple data sources
- Session identification using time-based clustering
- Risk assessment using pattern matching and scoring
- Domain analysis with suspicious indicator detection
"""

        # Add download breakdown
        download_analysis = self.report_data.get('download_analysis', {})
        file_breakdown = download_analysis.get('file_type_breakdown', {})

        technical_details += "\nDOWNLOAD FILE TYPE BREAKDOWN:\n"
        for file_type, count in file_breakdown.items():
            technical_details += f"- {file_type.title()}: {count:,}\n"

        return technical_details

    def generate_conclusions(self):
        """Generate conclusions section."""
        conclusions = """
CONCLUSIONS
{'='*15}

DIGITAL FORENSIC VALUE OF BROWSER ARTIFACTS:

This analysis demonstrates that browser artifacts provide significant forensic value
in reconstructing user activity, even when users attempt to delete their browsing data.
Key conclusions include:

1. PERSISTENCE OF DATA:
   Browser artifacts remain accessible through multiple storage mechanisms despite
   user deletion attempts. SQLite databases, cache files, and system logs preserve
   historical activity that can be recovered and analyzed.

2. TIMELINE RECONSTRUCTION:
   By correlating timestamps across multiple browsers and data sources, investigators
   can reconstruct detailed timelines of user activity, revealing patterns that might
   otherwise remain hidden.

3. SUSPICIOUS ACTIVITY DETECTION:
   Pattern analysis of domains, downloads, and behaviors can identify potentially
   malicious activity, including visits to suspicious sites and downloads of
   potentially harmful files.

4. PRIVACY IMPLICATIONS:
   The extensive cookie and tracking data collected reveals the level of surveillance
   and data collection that occurs during normal web browsing, highlighting privacy
   concerns for users.

5. INVESTIGATIVE TECHNIQUES:
   The combination of automated extraction tools and forensic analysis methods
   provides a comprehensive approach to browser artifact examination that can be
   applied to various investigative scenarios.

RECOMMENDATIONS:

For digital forensics practitioners:
- Always include browser artifact analysis in comprehensive investigations
- Use multiple correlation techniques to validate findings
- Maintain detailed documentation of analysis methods and tools used

For security awareness:
- Users should be educated about the persistence of browser data
- Privacy tools and secure browsing practices should be recommended
- Regular clearing of browser data may not provide complete privacy

This analysis serves as a foundation for understanding browser forensics and
demonstrates the importance of comprehensive digital evidence collection in
modern investigations.
"""
        return conclusions

    def generate_appendices(self):
        """Generate appendices with detailed data."""
        appendices = """
APPENDICES
{'='*10}

APPENDIX A: TOP DOMAINS VISITED
"""

        top_domains = self.report_data.get('domain_analysis', {}).get('top_domains', [])
        for i, (domain, visits) in enumerate(top_domains[:50], 1):
            appendices += "2d"

        appendices += """

APPENDIX B: SUSPICIOUS DOMAIN DETAILS
"""

        suspicious_domains = self.report_data.get('domain_analysis', {}).get('suspicious_domains', {})
        for domain, data in suspicious_domains.items():
            stats = data.get('stats', {})
            appendices += f"\nDomain: {domain}\n"
            appendices += f"Risk Level: {data.get('risk_level', 0)}\n"
            appendices += f"Visits: {stats.get('visits', 0)}\n"
            appendices += f"First Visit: {stats.get('first_visit', 'Unknown')}\n"
            appendices += f"Last Visit: {stats.get('last_visit', 'Unknown')}\n"
            appendices += f"Risk Factors: {', '.join(data.get('risk_factors', []))}\n"

        appendices += """

APPENDIX C: TOOLS AND METHODS
"""

        appendices += """
EXTRACTION TOOLS:
- browser_extractor.py: Custom Python script for multi-browser data extraction
- SQLite3 library: Database parsing and timestamp conversion
- CSV/JSON libraries: Data export and structured storage

ANALYSIS TOOLS:
- analyze_artifacts.py: Pattern analysis and timeline construction
- Timeline correlation algorithms: Multi-source data integration
- Risk assessment algorithms: Suspicious activity detection

VALIDATION METHODS:
- Cross-browser data correlation
- Timestamp consistency checking
- Pattern validation against known indicators
- Statistical analysis of activity patterns

DATA PRESERVATION:
- Original files never modified
- MD5/SHA256 hashing for integrity verification
- Chain of custody documentation
- Secure storage of extracted data
"""

        return appendices

    def save_report(self, report_content, filename=None):
        """Save the generated report to file."""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"browser_forensics_report_{timestamp}.txt"

        report_file = self.output_dir / filename
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_content)

        print(f"Forensic report saved to: {report_file}")
        return report_file

def main():
    parser = argparse.ArgumentParser(description='Generate forensic incident report from browser analysis')
    parser.add_argument('-a', '--analysis', default='../data/processed',
                       help='Analysis data directory (default: ../data/processed)')
    parser.add_argument('-o', '--output', default='../reports',
                       help='Output directory for reports (default: ../reports)')
    parser.add_argument('-c', '--case', default='BF-2025-001',
                       help='Case number for the report (default: BF-2025-001)')
    parser.add_argument('-i', '--investigator', default='Browser Forensics Team',
                       help='Investigator name (default: Browser Forensics Team)')
    parser.add_argument('-f', '--filename', help='Output filename (optional)')

    args = parser.parse_args()

    generator = ForensicReportGenerator(args.analysis, args.output)

    if not generator.report_data:
        print("Error: No analysis data found. Please run analysis first.")
        return

    print("Generating forensic incident report...")
    report_content = generator.generate_incident_report(args.case, args.investigator)
    report_file = generator.save_report(report_content, args.filename)

    print(f"Report generation completed: {report_file}")
    print("Report includes:")
    print("- Executive summary with key metrics")
    print("- Detailed findings and analysis")
    print("- Timeline reconstruction")
    print("- Session analysis")
    print("- Technical details and conclusions")

if __name__ == "__main__":
    main()
