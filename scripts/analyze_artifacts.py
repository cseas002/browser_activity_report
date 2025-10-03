#!/usr/bin/env python3
"""
Browser Artifact Analysis Tool for Digital Forensics

This script analyzes extracted browser artifacts to:
- Build chronological timelines of user activity
- Identify suspicious patterns and behaviors
- Correlate data across multiple browsers
- Generate forensic insights and reports

Author: Browser Forensics Project
Date: October 2025
"""

import os
import csv
import json
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, Counter
import re
from urllib.parse import urlparse

class BrowserAnalyzer:
    """Class for analyzing browser artifacts."""

    def __init__(self, input_dir="data/raw", output_dir="data/processed"):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Suspicious patterns and indicators
        self.suspicious_domains = {
            'darkweb': ['.onion', 'darkweb', 'tor'],
            'malware': ['malware', 'virus', 'trojan', 'ransomware'],
            'phishing': ['login', 'secure', 'account', 'verify', 'banking'],
            'adult': ['porn', 'sex', 'adult', 'xxx'],
            'gambling': ['casino', 'betting', 'poker', 'lottery']
        }

        self.suspicious_keywords = [
            'password', 'login', 'admin', 'root', 'hack', 'exploit',
            'crack', 'keygen', 'warez', 'torrent', 'pirate'
        ]

    def load_csv_data(self, filename):
        """Load data from CSV file."""
        filepath = self.input_dir / filename
        if not filepath.exists():
            print(f"Warning: {filepath} not found")
            return []

        data = []
        try:
            with open(filepath, 'r', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    # Convert datetime strings back to datetime objects
                    for key, value in row.items():
                        if 'time' in key.lower() and value:
                            try:
                                row[key] = datetime.fromisoformat(value)
                            except ValueError:
                                pass  # Keep as string if conversion fails
                    data.append(row)
        except Exception as e:
            print(f"Error loading {filepath}: {e}")

        return data

    def load_all_data(self):
        """Load all extracted browser data."""
        self.history_data = self.load_csv_data('browser_history.csv')
        self.download_data = self.load_csv_data('browser_downloads.csv')
        self.cookie_data = self.load_csv_data('browser_cookies.csv')

        print(f"Loaded {len(self.history_data)} history records")
        print(f"Loaded {len(self.download_data)} download records")
        print(f"Loaded {len(self.cookie_data)} cookie records")

    def build_timeline(self):
        """Build chronological timeline of all browser activities."""
        timeline_events = []

        # Add history events
        for item in self.history_data:
            if item.get('visit_time'):
                timeline_events.append({
                    'timestamp': item['visit_time'],
                    'type': 'history_visit',
                    'browser': item.get('browser', 'Unknown'),
                    'url': item.get('url', ''),
                    'title': item.get('title', ''),
                    'details': f"Visited: {item.get('title', 'Unknown')} ({item.get('url', '')})"
                })

        # Add download events
        for item in self.download_data:
            if item.get('start_time'):
                timeline_events.append({
                    'timestamp': item['start_time'],
                    'type': 'download_start',
                    'browser': item.get('browser', 'Unknown'),
                    'url': item.get('url', ''),
                    'target_path': item.get('target_path', ''),
                    'details': f"Download started: {item.get('target_path', '')} from {item.get('url', '')}"
                })

            if item.get('end_time'):
                timeline_events.append({
                    'timestamp': item['end_time'],
                    'type': 'download_complete',
                    'browser': item.get('browser', 'Unknown'),
                    'url': item.get('url', ''),
                    'target_path': item.get('target_path', ''),
                    'details': f"Download completed: {item.get('target_path', '')}"
                })

        # Add cookie events (creation and last access)
        for item in self.cookie_data:
            if item.get('creation_utc'):
                timeline_events.append({
                    'timestamp': item['creation_utc'],
                    'type': 'cookie_created',
                    'browser': item.get('browser', 'Unknown'),
                    'host': item.get('host_key', item.get('host', '')),
                    'name': item.get('name', ''),
                    'details': f"Cookie created: {item.get('name', '')} for {item.get('host_key', item.get('host', ''))}"
                })

            if item.get('last_access_utc') or item.get('lastAccessed'):
                access_time = item.get('last_access_utc') or item.get('lastAccessed')
                if access_time:
                    timeline_events.append({
                        'timestamp': access_time,
                        'type': 'cookie_accessed',
                        'browser': item.get('browser', 'Unknown'),
                        'host': item.get('host_key', item.get('host', '')),
                        'name': item.get('name', ''),
                        'details': f"Cookie accessed: {item.get('name', '')} for {item.get('host_key', item.get('host', ''))}"
                    })

        # Sort timeline by timestamp (handle mixed datetime/string types)
        def sort_key(event):
            timestamp = event['timestamp']
            if isinstance(timestamp, datetime):
                return timestamp
            elif isinstance(timestamp, str) and timestamp:
                try:
                    return datetime.fromisoformat(timestamp)
                except ValueError:
                    return datetime.min
            else:
                return datetime.min

        timeline_events.sort(key=sort_key)

        return timeline_events

    def analyze_domain_patterns(self):
        """Analyze domain access patterns and identify suspicious domains."""
        domain_stats = defaultdict(lambda: {'visits': 0, 'browsers': set(), 'first_visit': None, 'last_visit': None})

        for item in self.history_data:
            url = item.get('url', '')
            if url:
                try:
                    parsed = urlparse(url)
                    domain = parsed.netloc.lower()

                    # Remove www. prefix for analysis
                    if domain.startswith('www.'):
                        domain = domain[4:]

                    domain_stats[domain]['visits'] += 1
                    domain_stats[domain]['browsers'].add(item.get('browser', 'Unknown'))

                    visit_time = item.get('visit_time') or item.get('last_visit_time')
                    if visit_time:
                        if not domain_stats[domain]['first_visit'] or visit_time < domain_stats[domain]['first_visit']:
                            domain_stats[domain]['first_visit'] = visit_time
                        if not domain_stats[domain]['last_visit'] or visit_time > domain_stats[domain]['last_visit']:
                            domain_stats[domain]['last_visit'] = visit_time

                except Exception as e:
                    print(f"Error parsing URL {url}: {e}")

        # Identify suspicious domains
        suspicious_domains = {}
        for domain, stats in domain_stats.items():
            risk_level = self.assess_domain_risk(domain)
            if risk_level > 0:
                suspicious_domains[domain] = {
                    'stats': stats,
                    'risk_level': risk_level,
                    'risk_factors': self.get_risk_factors(domain)
                }

        return domain_stats, suspicious_domains

    def assess_domain_risk(self, domain):
        """Assess risk level of a domain based on known patterns."""
        risk_score = 0

        # Check for suspicious domain patterns
        for category, patterns in self.suspicious_domains.items():
            for pattern in patterns:
                if pattern in domain:
                    risk_score += 2 if category in ['darkweb', 'malware'] else 1

        # Check for suspicious keywords in domain
        for keyword in self.suspicious_keywords:
            if keyword in domain:
                risk_score += 1

        # Check for IP addresses (often suspicious)
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            risk_score += 1

        # Check for unusual TLDs or long domains
        if len(domain) > 50:
            risk_score += 1

        return risk_score

    def get_risk_factors(self, domain):
        """Get specific risk factors for a domain."""
        factors = []

        for category, patterns in self.suspicious_domains.items():
            for pattern in patterns:
                if pattern in domain:
                    factors.append(f"Contains '{pattern}' ({category})")

        for keyword in self.suspicious_keywords:
            if keyword in domain:
                factors.append(f"Contains suspicious keyword '{keyword}'")

        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            factors.append("IP address instead of domain name")

        if len(domain) > 50:
            factors.append("Unusually long domain name")

        return factors

    def analyze_download_patterns(self):
        """Analyze download patterns for suspicious activity."""
        download_stats = defaultdict(int)
        suspicious_downloads = []

        for item in self.download_data:
            url = item.get('url', '').lower()
            target_path = item.get('target_path', '').lower()

            # Categorize downloads
            if any(ext in target_path for ext in ['.exe', '.msi', '.dmg', '.pkg']):
                download_stats['executables'] += 1
            elif any(ext in target_path for ext in ['.zip', '.rar', '.7z', '.tar.gz']):
                download_stats['archives'] += 1
            elif any(ext in target_path for ext in ['.pdf', '.doc', '.docx', '.xls', '.xlsx']):
                download_stats['documents'] += 1
            elif any(ext in target_path for ext in ['.jpg', '.png', '.gif', '.mp4', '.avi']):
                download_stats['media'] += 1
            else:
                download_stats['other'] += 1

            # Check for suspicious download sources or names
            risk_score = 0
            risk_factors = []

            # Check URL for suspicious patterns
            for category, patterns in self.suspicious_domains.items():
                for pattern in patterns:
                    if pattern in url:
                        risk_score += 2
                        risk_factors.append(f"Downloaded from {category} source")

            # Check filename for suspicious patterns
            filename = os.path.basename(target_path)
            for keyword in self.suspicious_keywords:
                if keyword in filename:
                    risk_score += 1
                    risk_factors.append(f"Filename contains '{keyword}'")

            # Check for double extensions (often malicious)
            if filename.count('.') > 1:
                parts = filename.split('.')
                if any(ext in ['exe', 'scr', 'pif', 'com'] for ext in parts[1:]):
                    risk_score += 2
                    risk_factors.append("Double extension with executable")

            if risk_score > 0:
                suspicious_downloads.append({
                    'url': item.get('url', ''),
                    'target_path': item.get('target_path', ''),
                    'start_time': item.get('start_time'),
                    'end_time': item.get('end_time'),
                    'risk_score': risk_score,
                    'risk_factors': risk_factors,
                    'browser': item.get('browser', 'Unknown')
                })

        return download_stats, suspicious_downloads

    def analyze_cookie_patterns(self):
        """Analyze cookie patterns for tracking and session management."""
        cookie_stats = {
            'total_cookies': len(self.cookie_data),
            'secure_cookies': 0,
            'httponly_cookies': 0,
            'session_cookies': 0,
            'third_party_cookies': 0,
            'tracking_domains': defaultdict(int)
        }

        tracking_domains = [
            'google-analytics.com', 'doubleclick.net', 'facebook.com',
            'googletagmanager.com', 'hotjar.com', 'mixpanel.com'
        ]

        for item in self.cookie_data:
            # Count secure and httponly cookies
            if item.get('is_secure') or item.get('isSecure'):
                cookie_stats['secure_cookies'] += 1
            if item.get('is_httponly') or item.get('isHttpOnly'):
                cookie_stats['httponly_cookies'] += 1

            # Check for session cookies (no expiration or short-lived)
            expires = item.get('expires_utc') or item.get('expiry')
            if not expires or (isinstance(expires, datetime) and expires < datetime.now() + timedelta(hours=24)):
                cookie_stats['session_cookies'] += 1

            # Check for third-party cookies
            host = item.get('host_key', item.get('host', ''))
            if host and '.' in host:
                # Simple check for third-party (not matching current domain)
                cookie_stats['third_party_cookies'] += 1

                # Check for known tracking domains
                for tracking_domain in tracking_domains:
                    if tracking_domain in host:
                        cookie_stats['tracking_domains'][tracking_domain] += 1

        return cookie_stats

    def generate_session_analysis(self, timeline_events):
        """Analyze user sessions based on timeline events."""
        sessions = []
        current_session = None
        session_timeout = timedelta(minutes=30)  # Session timeout threshold

        def ensure_datetime(ts):
            """Ensure timestamp is a datetime object."""
            if isinstance(ts, datetime):
                return ts
            elif isinstance(ts, str) and ts:
                try:
                    return datetime.fromisoformat(ts)
                except ValueError:
                    return None
            return None

        for event in timeline_events:
            timestamp = ensure_datetime(event['timestamp'])
            if not timestamp:
                continue

            # Start new session if no current session or timeout exceeded
            if not current_session or (timestamp - current_session['end_time']) > session_timeout:
                if current_session:
                    sessions.append(current_session)

                current_session = {
                    'start_time': timestamp,
                    'end_time': timestamp,
                    'events': [],
                    'browsers': set(),
                    'domains': set(),
                    'activity_types': set()
                }

            # Update current session
            current_session['end_time'] = timestamp
            current_session['events'].append(event)
            current_session['browsers'].add(event['browser'])
            current_session['activity_types'].add(event['type'])

            # Extract domain from URL if available
            if event.get('url'):
                try:
                    parsed = urlparse(event['url'])
                    domain = parsed.netloc.lower()
                    if domain.startswith('www.'):
                        domain = domain[4:]
                    current_session['domains'].add(domain)
                except:
                    pass

        # Add final session
        if current_session:
            sessions.append(current_session)

        # Calculate session statistics
        session_stats = {
            'total_sessions': len(sessions),
            'avg_session_duration': None,
            'total_events': sum(len(s['events']) for s in sessions),
            'browsers_used': set(),
            'peak_activity_hours': defaultdict(int)
        }

        if sessions:
            durations = [(s['end_time'] - s['start_time']) for s in sessions if s['end_time'] and s['start_time']]
            if durations:
                avg_duration = sum(durations, timedelta()) / len(durations)
                session_stats['avg_session_duration'] = str(avg_duration)

            for session in sessions:
                session_stats['browsers_used'].update(session['browsers'])
                if session['start_time']:
                    session_stats['peak_activity_hours'][session['start_time'].hour] += 1

        session_stats['browsers_used'] = list(session_stats['browsers_used'])

        return sessions, session_stats

    def generate_report(self):
        """Generate comprehensive forensic analysis report."""
        print("Loading browser data...")
        self.load_all_data()

        print("Building timeline...")
        timeline = self.build_timeline()

        print("Analyzing domain patterns...")
        domain_stats, suspicious_domains = self.analyze_domain_patterns()

        print("Analyzing download patterns...")
        download_stats, suspicious_downloads = self.analyze_download_patterns()

        print("Analyzing cookie patterns...")
        cookie_stats = self.analyze_cookie_patterns()

        print("Analyzing user sessions...")
        sessions, session_stats = self.generate_session_analysis(timeline)

        # Generate summary report
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'summary': {
                'total_history_records': len(self.history_data),
                'total_download_records': len(self.download_data),
                'total_cookie_records': len(self.cookie_data),
                'unique_domains': len(domain_stats),
                'suspicious_domains': len(suspicious_domains),
                'suspicious_downloads': len(suspicious_downloads),
                'user_sessions': session_stats['total_sessions']
            },
            'timeline_events': len(timeline),
            'domain_analysis': {
                'top_domains': sorted(
                    [(domain, stats['visits']) for domain, stats in domain_stats.items()],
                    key=lambda x: x[1], reverse=True
                )[:20],
                'suspicious_domains': suspicious_domains
            },
            'download_analysis': {
                'file_type_breakdown': download_stats,
                'suspicious_downloads': suspicious_downloads
            },
            'cookie_analysis': cookie_stats,
            'session_analysis': session_stats,
            'key_findings': self.generate_key_findings(
                timeline, suspicious_domains, suspicious_downloads, session_stats
            )
        }

        return report, timeline, sessions

    def generate_key_findings(self, timeline, suspicious_domains, suspicious_downloads, session_stats):
        """Generate key forensic findings from the analysis."""
        findings = []

        # Check for suspicious domain activity
        if suspicious_domains:
            findings.append({
                'severity': 'HIGH',
                'category': 'Suspicious Domain Access',
                'description': f'Found {len(suspicious_domains)} potentially suspicious domains accessed',
                'details': list(suspicious_domains.keys())[:5]  # Top 5 suspicious domains
            })

        # Check for suspicious downloads
        if suspicious_downloads:
            findings.append({
                'severity': 'HIGH',
                'category': 'Suspicious Downloads',
                'description': f'Found {len(suspicious_downloads)} potentially suspicious downloads',
                'details': [f"{d['target_path']} from {d['url']}" for d in suspicious_downloads[:3]]
            })

        # Check for extensive tracking
        tracking_cookies = sum(session_stats.get('tracking_domains', {}).values())
        if tracking_cookies > 50:
            findings.append({
                'severity': 'MEDIUM',
                'category': 'Privacy Concerns',
                'description': f'Extensive tracking detected with {tracking_cookies} tracking cookies',
                'details': list(session_stats['tracking_domains'].keys())[:3]
            })

        # Check for unusual session patterns
        if session_stats['total_sessions'] > 100:
            findings.append({
                'severity': 'MEDIUM',
                'category': 'High Activity',
                'description': f'Unusually high number of browsing sessions ({session_stats["total_sessions"]})',
                'details': f'Average session duration: {session_stats.get("avg_session_duration", "Unknown")}'
            })

        # Check for late-night activity
        late_night_hours = sum(session_stats.get('peak_activity_hours', {}).get(hour, 0)
                             for hour in range(22, 24)) + sum(session_stats.get('peak_activity_hours', {}).get(hour, 0)
                             for hour in range(0, 6))
        if late_night_hours > session_stats['total_sessions'] * 0.3:  # More than 30% late night
            findings.append({
                'severity': 'LOW',
                'category': 'Activity Patterns',
                'description': 'Significant late-night browsing activity detected',
                'details': f'{late_night_hours} sessions between 10 PM and 6 AM'
            })

        return findings

    def save_analysis_results(self, report, timeline, sessions):
        """Save analysis results to files."""

        # Save main report
        report_file = self.output_dir / 'forensic_analysis_report.json'
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)

        # Save timeline as CSV
        timeline_file = self.output_dir / 'timeline_events.csv'
        if timeline:
            fieldnames = ['timestamp', 'type', 'browser', 'url', 'title', 'target_path', 'host', 'name', 'details']
            with open(timeline_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for event in timeline:
                    row = {field: event.get(field, '') for field in fieldnames}
                    row['timestamp'] = row['timestamp'].isoformat() if isinstance(row['timestamp'], datetime) else row['timestamp']
                    writer.writerow(row)

        # Save sessions analysis
        sessions_file = self.output_dir / 'user_sessions.json'
        with open(sessions_file, 'w', encoding='utf-8') as f:
            json.dump({
                'session_stats': report['session_analysis'],
                'sessions': [{
                    'start_time': s['start_time'].isoformat() if s['start_time'] else None,
                    'end_time': s['end_time'].isoformat() if s['end_time'] else None,
                    'duration': str(s['end_time'] - s['start_time']) if s['end_time'] and s['start_time'] else None,
                    'events_count': len(s['events']),
                    'browsers': list(s['browsers']),
                    'domains': list(s['domains']),
                    'activity_types': list(s['activity_types'])
                } for s in sessions]
            }, f, indent=2)

        print("Analysis results saved:")
        print(f"- Main report: {report_file}")
        print(f"- Timeline: {timeline_file}")
        print(f"- Sessions: {sessions_file}")

def main():
    parser = argparse.ArgumentParser(description='Analyze browser artifacts for forensic insights')
    parser.add_argument('-i', '--input', default='data/raw',
                       help='Input directory with extracted data (default: data/raw)')
    parser.add_argument('-o', '--output', default='data/processed',
                       help='Output directory for analysis results (default: data/processed)')

    args = parser.parse_args()

    analyzer = BrowserAnalyzer(args.input, args.output)
    report, timeline, sessions = analyzer.generate_report()
    analyzer.save_analysis_results(report, timeline, sessions)

    print("\nAnalysis Summary:")
    print(f"- Timeline events: {len(timeline)}")
    print(f"- User sessions: {len(sessions)}")
    print(f"- Suspicious domains: {len(report['domain_analysis']['suspicious_domains'])}")
    print(f"- Suspicious downloads: {len(report['download_analysis']['suspicious_downloads'])}")
    print(f"- Key findings: {len(report['key_findings'])}")

    if report['key_findings']:
        print("\nKey Findings:")
        for finding in report['key_findings'][:3]:  # Show top 3 findings
            print(f"- {finding['severity']}: {finding['description']}")

if __name__ == "__main__":
    main()
