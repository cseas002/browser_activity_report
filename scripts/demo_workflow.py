#!/usr/bin/env python3
"""
Browser Forensics Demonstration Workflow

This script demonstrates the complete browser forensics workflow:
1. Generate sample browser data
2. Extract and analyze artifacts
3. Generate forensic report

Author: Browser Forensics Project
Date: October 2025
"""

import os
import csv
import json
import sqlite3
from datetime import datetime, timedelta
import random
from pathlib import Path

class BrowserForensicsDemo:
    """Demonstration class for browser forensics workflow."""

    def __init__(self, demo_dir="demo_data"):
        self.demo_dir = Path(demo_dir)
        self.demo_dir.mkdir(exist_ok=True)

        # Sample data for demonstration
        self.sample_domains = [
            # Normal domains
            ('google.com', 'Google Search', 'Search Engine'),
            ('github.com', 'GitHub', 'Development Platform'),
            ('stackoverflow.com', 'Stack Overflow', 'Programming Q&A'),
            ('kth.se', 'KTH Royal Institute of Technology', 'Education'),
            ('youtube.com', 'YouTube', 'Video Platform'),

            # Potentially suspicious domains
            ('suspicious-site.com', 'Suspicious Content', 'Questionable'),
            ('darkweb-market.onion', 'Dark Web Market', 'Illegal'),
            ('malware-download.net', 'Free Downloads', 'Malicious'),
            ('phishing-bank.com', 'Online Banking', 'Phishing'),
            ('tracker-analytics.com', 'Analytics Service', 'Tracking'),
        ]

        self.sample_downloads = [
            ('https://github.com/user/repo/archive/main.zip', 'repo-main.zip', 'application/zip'),
            ('https://example.com/document.pdf', 'document.pdf', 'application/pdf'),
            ('https://suspicious-site.com/tool.exe', 'tool.exe', 'application/x-msdownload'),
            ('https://trusted-source.com/update.msi', 'update.msi', 'application/x-msi'),
            ('https://media-site.com/video.mp4', 'video.mp4', 'video/mp4'),
        ]

    def create_sample_chrome_history(self):
        """Create sample Chrome history database."""
        print("Creating sample Chrome history...")

        # Create directories
        chrome_dir = self.demo_dir / "chrome_profile"
        chrome_dir.mkdir(exist_ok=True)

        # Create sample history database
        history_db = chrome_dir / "History"
        conn = sqlite3.connect(str(history_db))
        cursor = conn.cursor()

        # Create tables
        cursor.execute('''
            CREATE TABLE urls (
                id INTEGER PRIMARY KEY,
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                last_visit_time INTEGER
            )
        ''')

        cursor.execute('''
            CREATE TABLE visits (
                id INTEGER PRIMARY KEY,
                url INTEGER,
                visit_time INTEGER,
                from_visit INTEGER,
                visit_duration INTEGER
            )
        ''')

        # Chrome timestamp base (microseconds since 1601-01-01)
        chrome_base = 11644473600000000
        base_time = int((datetime.now() - timedelta(days=7)).timestamp() * 1000000)

        # Insert sample URLs and visits
        url_id = 1
        visit_id = 1

        for domain, title, category in self.sample_domains:
            url = f"https://{domain}/page{random.randint(1,10)}"
            visit_count = random.randint(1, 20)

            # Insert URL
            cursor.execute(
                'INSERT INTO urls VALUES (?, ?, ?, ?, ?)',
                (url_id, url, f"{title} - Page", visit_count,
                 chrome_base + base_time + random.randint(0, 604800000000))  # Random time within week
            )

            # Insert visits
            for i in range(visit_count):
                visit_time = chrome_base + base_time + (i * 86400000000) + random.randint(0, 3600000000)
                cursor.execute(
                    'INSERT INTO visits VALUES (?, ?, ?, ?, ?)',
                    (visit_id, url_id, visit_time, 0 if i == 0 else visit_id - 1, random.randint(1000000, 300000000))
                )
                visit_id += 1

            url_id += 1

        conn.commit()
        conn.close()
        print(f"Created sample Chrome history at {history_db}")

    def create_sample_firefox_history(self):
        """Create sample Firefox history database."""
        print("Creating sample Firefox history...")

        firefox_dir = self.demo_dir / "firefox_profile"
        firefox_dir.mkdir(exist_ok=True)

        places_db = firefox_dir / "places.sqlite"
        conn = sqlite3.connect(str(places_db))
        cursor = conn.cursor()

        # Create Firefox places table
        cursor.execute('''
            CREATE TABLE moz_places (
                id INTEGER PRIMARY KEY,
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                last_visit_date INTEGER
            )
        ''')

        cursor.execute('''
            CREATE TABLE moz_historyvisits (
                id INTEGER PRIMARY KEY,
                place_id INTEGER,
                visit_date INTEGER,
                from_visit INTEGER
            )
        ''')

        # Firefox uses microseconds since 1970-01-01 (Unix timestamp * 1000000)
        base_time = int((datetime.now() - timedelta(days=7)).timestamp() * 1000000)

        place_id = 1
        visit_id = 1

        for domain, title, category in self.sample_domains[:7]:  # Fewer entries for Firefox
            url = f"https://{domain}/article{random.randint(1,5)}"

            cursor.execute(
                'INSERT INTO moz_places VALUES (?, ?, ?, ?, ?)',
                (place_id, url, f"{title} - Article", random.randint(1, 15),
                 base_time + random.randint(0, 604800000000))
            )

            # Add some visits
            for i in range(random.randint(1, 5)):
                visit_time = base_time + (i * 86400000000) + random.randint(0, 3600000000)
                cursor.execute(
                    'INSERT INTO moz_historyvisits VALUES (?, ?, ?, ?)',
                    (visit_id, place_id, visit_time, 0 if i == 0 else visit_id - 1)
                )
                visit_id += 1

            place_id += 1

        conn.commit()
        conn.close()
        print(f"Created sample Firefox history at {places_db}")

    def create_sample_downloads(self):
        """Create sample download records."""
        print("Creating sample download data...")

        downloads_file = self.demo_dir / "downloads.csv"

        with open(downloads_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['browser', 'target_path', 'url', 'start_time', 'end_time',
                           'received_bytes', 'total_bytes', 'danger_type', 'opened'])

            base_time = datetime.now() - timedelta(days=7)

            for url, filename, mime_type in self.sample_downloads:
                start_time = base_time + timedelta(hours=random.randint(0, 168))
                duration = timedelta(seconds=random.randint(1, 300))
                end_time = start_time + duration

                file_size = random.randint(1024, 10485760)  # 1KB to 10MB

                writer.writerow([
                    'Chrome',
                    f'/Users/demo/Downloads/{filename}',
                    url,
                    start_time.isoformat(),
                    end_time.isoformat(),
                    file_size,
                    file_size,
                    0,  # No danger
                    random.choice([0, 1])  # Sometimes opened
                ])

        print(f"Created sample downloads at {downloads_file}")

    def create_sample_cookies(self):
        """Create sample cookie data."""
        print("Creating sample cookie data...")

        cookies_file = self.demo_dir / "cookies.csv"

        with open(cookies_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['browser', 'host_key', 'name', 'value', 'path',
                           'expires_utc', 'is_secure', 'is_httponly',
                           'last_access_utc', 'creation_utc'])

            base_time = datetime.now() - timedelta(days=30)
            chrome_base = 11644473600000000

            # Sample cookies
            cookies_data = [
                ('.google.com', 'session_id', 'abc123', '/', True, False),
                ('github.com', 'user_session', 'xyz789', '/', True, True),
                ('kth.se', 'login_token', 'token123', '/', True, True),
                ('tracker-analytics.com', '_ga', 'GA1.1.123456789', '/', False, False),
                ('youtube.com', 'PREF', 'f1=10000000', '/', False, False),
            ]

            for host, name, value, path, secure, httponly in cookies_data:
                creation_time = base_time + timedelta(days=random.randint(0, 30))
                last_access = creation_time + timedelta(hours=random.randint(1, 720))
                expires = creation_time + timedelta(days=random.randint(30, 365))

                writer.writerow([
                    'Chrome',
                    host,
                    name,
                    value,
                    path,
                    (chrome_base + int(expires.timestamp() * 1000000)),
                    1 if secure else 0,
                    1 if httponly else 0,
                    (chrome_base + int(last_access.timestamp() * 1000000)),
                    (chrome_base + int(creation_time.timestamp() * 1000000))
                ])

        print(f"Created sample cookies at {cookies_file}")

    def run_demo_workflow(self):
        """Run the complete demonstration workflow."""
        print("=========================================")
        print("Browser Forensics Demonstration")
        print("=========================================")
        print()

        # Step 1: Create sample data
        print("Step 1: Creating sample browser data...")
        self.create_sample_chrome_history()
        self.create_sample_firefox_history()
        self.create_sample_downloads()
        self.create_sample_cookies()
        print()

        # Step 2: Extract data using our scripts
        print("Step 2: Extracting browser artifacts...")

        # Import our extraction script
        import sys
        sys.path.append('scripts')

        try:
            from browser_extractor import BrowserExtractor

            # Extract from demo data
            extractor = BrowserExtractor("demo_output/raw")

            # Mock the browser paths to use our demo data
            custom_paths = {
                'chrome': self.demo_dir / "chrome_profile",
                'firefox': self.demo_dir / "firefox_profile"
            }

            all_data = extractor.extract_all_browsers(custom_paths)
            extractor.save_all_data(all_data)

            print(f"Extracted {len(all_data['history'])} history records")
            print(f"Extracted {len(all_data['downloads'])} download records")
            print(f"Extracted {len(all_data['cookies'])} cookie records")

        except ImportError as e:
            print(f"Could not import extraction script: {e}")
            print("Please ensure the scripts are properly set up.")
            return
        except Exception as e:
            print(f"Error during extraction: {e}")
            return

        print()

        # Step 3: Analyze the data
        print("Step 3: Analyzing extracted artifacts...")

        try:
            from analyze_artifacts import BrowserAnalyzer

            analyzer = BrowserAnalyzer("demo_output/raw", "demo_output/processed")
            report, timeline, sessions = analyzer.generate_report()
            analyzer.save_analysis_results(report, timeline, sessions)

            print(f"Analysis complete: {len(timeline)} timeline events, {len(sessions)} sessions")

        except ImportError as e:
            print(f"Could not import analysis script: {e}")
            return
        except Exception as e:
            print(f"Error during analysis: {e}")
            return

        print()

        # Step 4: Generate report
        print("Step 4: Generating forensic report...")

        try:
            from generate_report import ForensicReportGenerator

            generator = ForensicReportGenerator("demo_output/processed", "demo_reports")
            report_content = generator.generate_incident_report("DEMO-2025-001", "Demo Investigator")
            report_file = generator.save_report(report_content, "demo_forensic_report.txt")

            print(f"Report generated: {report_file}")

        except ImportError as e:
            print(f"Could not import report generator: {e}")
            return
        except Exception as e:
            print(f"Error during report generation: {e}")
            return

        print()
        print("=========================================")
        print("Demonstration Complete!")
        print("=========================================")
        print()
        print("Demo files created:")
        print(f"- Sample data: {self.demo_dir}/")
        print(f"- Extracted data: demo_output/raw/")
        print(f"- Analysis results: demo_output/processed/")
        print(f"- Forensic report: demo_reports/demo_forensic_report.txt")
        print()
        print("Key findings from demo:")
        print(f"- {len(report.get('domain_analysis', {}).get('suspicious_domains', {}))} suspicious domains detected")
        print(f"- {len(report.get('download_analysis', {}).get('suspicious_downloads', []))} suspicious downloads found")
        print(f"- {report.get('summary', {}).get('user_sessions', 0)} user sessions identified")
        print()
        print("This demonstrates how browser artifacts persist despite")
        print("user attempts to delete browsing history and can be")
        print("reconstructed to reveal user activity patterns.")

def main():
    """Main demonstration function."""
    demo = BrowserForensicsDemo()

    print("This demonstration will create sample browser data and")
    print("show the complete forensics workflow.")
    print()

    response = input("Continue with demonstration? (y/N): ").lower().strip()
    if response not in ['y', 'yes']:
        print("Demonstration cancelled.")
        return

    demo.run_demo_workflow()

if __name__ == "__main__":
    main()
