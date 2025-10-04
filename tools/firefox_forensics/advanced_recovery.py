#!/usr/bin/env python3
"""
Advanced Firefox History Recovery Tool
Uses multiple forensic techniques to recover deleted history
"""

import sqlite3
import json
import struct
import lz4.block
import re
import logging
import csv
from pathlib import Path
from datetime import datetime
import tempfile
import shutil

class AdvancedFirefoxRecovery:
    def __init__(self, profile_path):
        self.profile_path = Path(profile_path)
        self.output_dir = Path("data/raw")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Configure logging
        logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
        
    def recover_from_wal(self):
        """Recover deleted history from WAL file"""
        wal_path = self.profile_path / "places.sqlite-wal"
        if not wal_path.exists():
            return []
            
        recovered = []
        try:
            with open(wal_path, 'rb') as f:
                wal_data = f.read()
                
            # Look for URL patterns in WAL
            url_pattern = rb'https?://[^\s\x00-\x1F\x7F-\xFF]{3,}'
            urls = re.finditer(url_pattern, wal_data)
            
            for match in urls:
                url = match.group(0).decode('utf-8', errors='ignore')
                if url and not url.startswith(('about:', 'place:')):
                    recovered.append({
                        'url': url,
                        'title': '[Recovered from WAL]',
                        'recovery_method': 'wal_recovery'
                    })
                    
        except Exception as e:
            logging.error(f"Error reading WAL file: {e}")
            
        return recovered
        
    def recover_from_journal(self):
        """Recover deleted history from journal file"""
        journal_path = self.profile_path / "places.sqlite-journal"
        if not journal_path.exists():
            return []
            
        recovered = []
        try:
            with open(journal_path, 'rb') as f:
                journal_data = f.read()
                
            # Look for URL patterns in journal
            url_pattern = rb'https?://[^\s\x00-\x1F\x7F-\xFF]{3,}'
            urls = re.finditer(url_pattern, journal_data)
            
            for match in urls:
                url = match.group(0).decode('utf-8', errors='ignore')
                if url and not url.startswith(('about:', 'place:')):
                    recovered.append({
                        'url': url,
                        'title': '[Recovered from Journal]',
                        'recovery_method': 'journal_recovery'
                    })
                    
        except Exception as e:
            logging.error(f"Error reading journal file: {e}")
            
        return recovered
        
    def recover_from_session_files(self):
        """Recover from all available session files"""
        recovered = []
        session_dir = self.profile_path / "sessionstore-backups"
        
        if not session_dir.exists():
            return recovered
            
        # Get all session files
        session_files = list(session_dir.glob("*.jsonlz4"))
        session_files.extend(list(session_dir.glob("*.baklz4")))
        
        for session_file in session_files:
            try:
                with open(session_file, 'rb') as f:
                    # Check for LZ4 header
                    header = f.read(8)
                    if header == b'mozLz40\0':
                        expected_size = struct.unpack('<I', f.read(4))[0]
                        compressed_data = f.read()
                        
                        try:
                            json_data = lz4.block.decompress(compressed_data, uncompressed_size=expected_size)
                            session_data = json.loads(json_data)
                            
                            # Extract URLs from all windows and tabs
                            for window in session_data.get('windows', []):
                                for tab in window.get('tabs', []):
                                    entries = tab.get('entries', [])
                                    for entry in entries:
                                        url = entry.get('url', '')
                                        title = entry.get('title', '')
                                        
                                        if url and not url.startswith(('about:', 'place:')):
                                            recovered.append({
                                                'url': url,
                                                'title': f'[Session] {title}',
                                                'recovery_method': f'session_{session_file.name}'
                                            })
                                            
                        except Exception as e:
                            logging.error(f"Error decompressing {session_file}: {e}")
                            
            except Exception as e:
                logging.error(f"Error reading {session_file}: {e}")
                
        return recovered
        
    def recover_from_database_free_space(self):
        """Recover from database free space using binary analysis"""
        places_db = self.profile_path / "places.sqlite"
        if not places_db.exists():
            return []
            
        recovered = []
        
        # Create a copy for analysis
        with tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False) as temp_db:
            temp_path = Path(temp_db.name)
            shutil.copy2(places_db, temp_path)
            
        try:
            # Read database as binary
            with open(temp_path, 'rb') as f:
                db_data = f.read()
                
            # Look for URL patterns in the entire database
            url_pattern = rb'https?://[^\s\x00-\x1F\x7F-\xFF]{3,}'
            urls = re.finditer(url_pattern, db_data)
            
            seen_urls = set()
            for match in urls:
                url = match.group(0).decode('utf-8', errors='ignore')
                if url and url not in seen_urls and not url.startswith(('about:', 'place:')):
                    seen_urls.add(url)
                    
                    # Try to find title near URL
                    start = max(0, match.start() - 200)
                    end = min(len(db_data), match.end() + 200)
                    surrounding = db_data[start:end]
                    
                    # Look for title patterns
                    title_pattern = rb'[A-Za-z0-9\s\-_]{3,}'
                    titles = re.finditer(title_pattern, surrounding)
                    title = ""
                    for t in titles:
                        candidate = t.group(0).decode('utf-8', errors='ignore')
                        if len(candidate) > len(title) and candidate not in url:
                            title = candidate
                            
                    recovered.append({
                        'url': url,
                        'title': f'[Free Space] {title}' if title else '[Free Space]',
                        'recovery_method': 'database_free_space'
                    })
                    
        except Exception as e:
            logging.error(f"Error analyzing database free space: {e}")
        finally:
            temp_path.unlink(missing_ok=True)
            
        return recovered
        
    def recover_from_cookies(self):
        """Try to recover URLs from cookie data"""
        cookies_db = self.profile_path / "cookies.sqlite"
        if not cookies_db.exists():
            return []
            
        recovered = []
        
        try:
            conn = sqlite3.connect(str(cookies_db))
            cursor = conn.cursor()
            
            # Get all unique hosts from cookies
            cursor.execute("SELECT DISTINCT host FROM moz_cookies WHERE host IS NOT NULL")
            hosts = cursor.fetchall()
            
            for (host,) in hosts:
                if host and not host.startswith('.'):
                    # Try to reconstruct URLs from cookie hosts
                    if not host.startswith(('localhost', '127.0.0.1')):
                        url = f"https://{host}"
                        recovered.append({
                            'url': url,
                            'title': f'[From Cookies] {host}',
                            'recovery_method': 'cookie_analysis'
                        })
                        
            conn.close()
            
        except Exception as e:
            logging.error(f"Error analyzing cookies: {e}")
            
        return recovered
        
    def recover_all(self):
        """Run all recovery methods and combine results"""
        all_recovered = []
        
        logging.info("Starting advanced Firefox history recovery...")
        
        # Method 1: WAL file
        logging.info("Recovering from WAL file...")
        wal_recovered = self.recover_from_wal()
        all_recovered.extend(wal_recovered)
        logging.info(f"Found {len(wal_recovered)} entries in WAL")
        
        # Method 2: Journal file
        logging.info("Recovering from journal file...")
        journal_recovered = self.recover_from_journal()
        all_recovered.extend(journal_recovered)
        logging.info(f"Found {len(journal_recovered)} entries in journal")
        
        # Method 3: Session files
        logging.info("Recovering from session files...")
        session_recovered = self.recover_from_session_files()
        all_recovered.extend(session_recovered)
        logging.info(f"Found {len(session_recovered)} entries in session files")
        
        # Method 4: Database free space
        logging.info("Recovering from database free space...")
        free_space_recovered = self.recover_from_database_free_space()
        all_recovered.extend(free_space_recovered)
        logging.info(f"Found {len(free_space_recovered)} entries in free space")
        
        # Method 5: Cookie analysis
        logging.info("Recovering from cookie analysis...")
        cookie_recovered = self.recover_from_cookies()
        all_recovered.extend(cookie_recovered)
        logging.info(f"Found {len(cookie_recovered)} entries from cookies")
        
        # Remove duplicates
        seen_urls = set()
        unique_recovered = []
        for entry in all_recovered:
            if entry['url'] not in seen_urls:
                seen_urls.add(entry['url'])
                unique_recovered.append(entry)
                
        logging.info(f"Total unique recovered entries: {len(unique_recovered)}")
        
        return unique_recovered
        
    def save_results(self, recovered_entries):
        """Save recovered entries to CSV"""
        output_file = self.output_dir / "advanced_firefox_recovery.csv"
        
        fieldnames = ['url', 'title', 'recovery_method']
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for entry in recovered_entries:
                writer.writerow(entry)
                
        logging.info(f"Saved {len(recovered_entries)} recovered entries to {output_file}")

def main():
    import sys
    if len(sys.argv) != 2:
        print("Usage: advanced_recovery.py path/to/firefox/profile")
        sys.exit(1)
        
    profile_path = Path(sys.argv[1])
    if not profile_path.exists():
        print(f"Profile directory not found: {profile_path}")
        sys.exit(1)
        
    recovery = AdvancedFirefoxRecovery(profile_path)
    recovered = recovery.recover_all()
    recovery.save_results(recovered)
    
    print(f"\nRecovery complete! Found {len(recovered)} deleted history entries.")
    print("Results saved to data/raw/advanced_firefox_recovery.csv")

if __name__ == "__main__":
    main()
