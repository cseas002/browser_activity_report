#!/usr/bin/env python3
"""
Browser Artifact Extraction Tool for Digital Forensics

This script extracts browser artifacts including history, cookies, downloads,
and cache data from multiple browsers for forensic analysis.

Supported Browsers:
- Google Chrome/Chromium
- Mozilla Firefox
- Apple Safari
- Microsoft Edge

Author: Browser Forensics Project
Date: October 2025
"""

import os
import sqlite3
import json
import csv
import shutil
import platform
import argparse
from datetime import datetime, timedelta
from pathlib import Path
import plistlib
import struct

class BrowserExtractor:
    """Main class for extracting browser artifacts."""

    def __init__(self, output_dir="data/raw"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.system = platform.system().lower()
        self.timestamp_base = {
            'chrome': 11644473600000000,  # Chrome uses microseconds since 1601-01-01
            'firefox': 0,  # Firefox uses microseconds since 1970-01-01 (Unix timestamp * 1000000)
            'safari': 978307200  # Safari uses seconds since 2001-01-01
        }

    def get_browser_paths(self):
        """Get default browser profile paths for different operating systems."""
        paths = {}

        if self.system == "windows":
            paths = {
                'chrome': Path(os.environ.get('LOCALAPPDATA', '')) / "Google" / "Chrome" / "User Data" / "Default",
                'firefox': Path(os.environ.get('APPDATA', '')) / "Mozilla" / "Firefox" / "Profiles",
                'edge': Path(os.environ.get('LOCALAPPDATA', '')) / "Microsoft" / "Edge" / "User Data" / "Default",
                'safari': None  # Safari not available on Windows
            }
        elif self.system == "darwin":  # macOS
            paths = {
                'chrome': Path.home() / "Library" / "Application Support" / "Google" / "Chrome" / "Default",
                'firefox': Path.home() / "Library" / "Application Support" / "Firefox" / "Profiles",
                'safari': Path.home() / "Library" / "Safari",
                'edge': None  # Edge path on macOS if installed
            }
        elif self.system == "linux":
            paths = {
                'chrome': Path.home() / ".config" / "google-chrome" / "Default",
                'firefox': Path.home() / ".mozilla" / "firefox",
                'safari': None,  # Safari not available on Linux
                'edge': None
            }

        return paths

    def chrome_timestamp_to_datetime(self, timestamp):
        """Convert Chrome timestamp to datetime."""
        if timestamp == 0:
            return None
        # Chrome uses microseconds since 1601-01-01
        base_date = datetime(1601, 1, 1)
        return base_date + timedelta(microseconds=timestamp)

    def firefox_timestamp_to_datetime(self, timestamp):
        """Convert Firefox timestamp to datetime."""
        if timestamp == 0:
            return None
        # Firefox uses microseconds since 1970-01-01
        return datetime.fromtimestamp(timestamp / 1000000)

    def safari_timestamp_to_datetime(self, timestamp):
        """Convert Safari timestamp to datetime."""
        if timestamp == 0:
            return None
        # Safari uses seconds since 2001-01-01
        base_date = datetime(2001, 1, 1)
        return base_date + timedelta(seconds=timestamp)

    def extract_chrome_history(self, profile_path):
        """Extract Chrome browsing history."""
        history_db = profile_path / "History"
        if not history_db.exists():
            print(f"Chrome History database not found: {history_db}")
            return []

        # Copy database to avoid locking issues
        temp_db = self.output_dir / "chrome_history_temp.db"
        shutil.copy2(history_db, temp_db)

        history_data = []
        try:
            conn = sqlite3.connect(str(temp_db))
            cursor = conn.cursor()

            # Query history with visit information
            query = """
            SELECT urls.url, urls.title, urls.visit_count, visits.visit_time
            FROM urls
            LEFT JOIN visits ON urls.id = visits.url
            WHERE visits.visit_time IS NOT NULL
            ORDER BY visits.visit_time DESC
            """

            cursor.execute(query)
            rows = cursor.fetchall()

            for row in rows:
                url, title, visit_count, visit_time = row
                history_data.append({
                    'browser': 'Chrome',
                    'url': url,
                    'title': title or '',
                    'visit_count': visit_count or 0,
                    'visit_time': self.chrome_timestamp_to_datetime(visit_time or 0)
                })

            conn.close()

        except sqlite3.Error as e:
            print(f"Error reading Chrome history: {e}")
        finally:
            # Clean up temp database
            if temp_db.exists():
                temp_db.unlink()

        # Try to recover deleted Chrome history
        deleted_history = self.extract_chrome_deleted_history(profile_path)
        history_data.extend(deleted_history)

        return history_data

    def extract_chrome_downloads(self, profile_path):
        """Extract Chrome download history."""
        # Try different possible locations for downloads database
        possible_dbs = [
            profile_path / "History",  # Downloads might be in History
            profile_path / "Downloads",  # Separate Downloads database (newer Chrome)
        ]

        downloads_db = None
        for db_path in possible_dbs:
            if db_path.exists():
                downloads_db = db_path
                break

        if not downloads_db:
            print(f"Chrome downloads database not found in profile: {profile_path}")
            return []

        temp_db = self.output_dir / "chrome_downloads_temp.db"
        try:
            shutil.copy2(downloads_db, temp_db)
        except (OSError, PermissionError) as e:
            print(f"Cannot access Chrome downloads database: {e}")
            return []

        downloads_data = []
        try:
            conn = sqlite3.connect(str(temp_db))
            cursor = conn.cursor()

            # Check if downloads table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='downloads'")
            if not cursor.fetchone():
                print("Chrome downloads table not found in database")
                conn.close()
                return []

            # Get column names to handle different schemas
            cursor.execute("PRAGMA table_info(downloads)")
            columns = {col[1]: col[0] for col in cursor.fetchall()}

            # Build query based on available columns
            select_columns = []
            if 'target_path' in columns:
                select_columns.append('downloads.target_path')
            if 'url' in columns:
                select_columns.append('downloads.url')
            if 'start_time' in columns:
                select_columns.append('downloads.start_time')
            if 'end_time' in columns:
                select_columns.append('downloads.end_time')
            if 'received_bytes' in columns:
                select_columns.append('downloads.received_bytes')
            if 'total_bytes' in columns:
                select_columns.append('downloads.total_bytes')
            if 'danger_type' in columns:
                select_columns.append('downloads.danger_type')
            if 'opened' in columns:
                select_columns.append('downloads.opened')

            if not select_columns:
                print("No recognizable columns found in Chrome downloads table")
                conn.close()
                return []

            query = f"""
            SELECT {', '.join(select_columns)}
            FROM downloads
            ORDER BY start_time DESC
            """

            cursor.execute(query)
            rows = cursor.fetchall()

            for row in rows:
                download_info = {'browser': 'Chrome'}

                # Map row data to dictionary based on available columns
                col_idx = 0
                if 'target_path' in columns:
                    download_info['target_path'] = row[col_idx] or ''
                    col_idx += 1
                if 'url' in columns:
                    download_info['url'] = row[col_idx] or ''
                    col_idx += 1
                if 'start_time' in columns:
                    download_info['start_time'] = self.chrome_timestamp_to_datetime(row[col_idx] or 0)
                    col_idx += 1
                if 'end_time' in columns:
                    download_info['end_time'] = self.chrome_timestamp_to_datetime(row[col_idx] or 0)
                    col_idx += 1
                if 'received_bytes' in columns:
                    download_info['received_bytes'] = row[col_idx] or 0
                    col_idx += 1
                if 'total_bytes' in columns:
                    download_info['total_bytes'] = row[col_idx] or 0
                    col_idx += 1
                if 'danger_type' in columns:
                    download_info['danger_type'] = row[col_idx] or 0
                    col_idx += 1
                if 'opened' in columns:
                    download_info['opened'] = bool(row[col_idx] or 0)
                    col_idx += 1

                downloads_data.append(download_info)

            conn.close()

        except sqlite3.Error as e:
            print(f"Error reading Chrome downloads: {e}")
        except Exception as e:
            print(f"Unexpected error reading Chrome downloads: {e}")
        finally:
            if temp_db.exists():
                temp_db.unlink()

        return downloads_data

    def extract_chrome_cookies(self, profile_path):
        """Extract Chrome cookies."""
        cookies_db = profile_path / "Cookies"
        if not cookies_db.exists():
            print(f"Chrome Cookies database not found: {cookies_db}")
            return []

        temp_db = self.output_dir / "chrome_cookies_temp.db"
        shutil.copy2(cookies_db, temp_db)

        cookies_data = []
        try:
            conn = sqlite3.connect(str(temp_db))
            cursor = conn.cursor()

            query = """
            SELECT host_key, name, value, path, expires_utc, is_secure, is_httponly,
                   last_access_utc, has_expires, is_persistent, creation_utc
            FROM cookies
            ORDER BY last_access_utc DESC
            """

            cursor.execute(query)
            rows = cursor.fetchall()

            for row in rows:
                host_key, name, value, path, expires_utc, is_secure, is_httponly, last_access_utc, has_expires, is_persistent, creation_utc = row
                cookies_data.append({
                    'browser': 'Chrome',
                    'host_key': host_key,
                    'name': name,
                    'value': value,
                    'path': path,
                    'expires_utc': self.chrome_timestamp_to_datetime(expires_utc or 0),
                    'is_secure': bool(is_secure),
                    'is_httponly': bool(is_httponly),
                    'last_access_utc': self.chrome_timestamp_to_datetime(last_access_utc or 0),
                    'has_expires': bool(has_expires),
                    'is_persistent': bool(is_persistent),
                    'creation_utc': self.chrome_timestamp_to_datetime(creation_utc or 0)
                })

            conn.close()

        except sqlite3.Error as e:
            print(f"Error reading Chrome cookies: {e}")
        finally:
            if temp_db.exists():
                temp_db.unlink()

        return cookies_data

    def extract_firefox_history(self, profile_path):
        """Extract Firefox browsing history."""
        places_db = profile_path / "places.sqlite"
        if not places_db.exists():
            print(f"Firefox places.sqlite not found: {places_db}")
            return []

        temp_db = self.output_dir / "firefox_places_temp.db"
        shutil.copy2(places_db, temp_db)

        history_data = []
        try:
            conn = sqlite3.connect(str(temp_db))
            cursor = conn.cursor()

            query = """
            SELECT moz_places.url, moz_places.title, moz_places.visit_count, moz_historyvisits.visit_date
            FROM moz_places
            LEFT JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id
            WHERE moz_historyvisits.visit_date IS NOT NULL
            ORDER BY moz_historyvisits.visit_date DESC
            """

            cursor.execute(query)
            rows = cursor.fetchall()

            for row in rows:
                url, title, visit_count, visit_date = row
                history_data.append({
                    'browser': 'Firefox',
                    'url': url,
                    'title': title or '',
                    'visit_count': visit_count or 0,
                    'visit_time': self.firefox_timestamp_to_datetime(visit_date or 0)
                })

            conn.close()

        except sqlite3.Error as e:
            print(f"Error reading Firefox history: {e}")
        finally:
            if temp_db.exists():
                temp_db.unlink()

        return history_data

    def extract_firefox_cookies(self, profile_path):
        """Extract Firefox cookies."""
        cookies_db = profile_path / "cookies.sqlite"
        if not cookies_db.exists():
            print(f"Firefox cookies.sqlite not found: {cookies_db}")
            return []

        temp_db = self.output_dir / "firefox_cookies_temp.db"
        shutil.copy2(cookies_db, temp_db)

        cookies_data = []
        try:
            conn = sqlite3.connect(str(temp_db))
            cursor = conn.cursor()

            query = """
            SELECT host, name, value, path, expiry, isSecure, isHttpOnly,
                   lastAccessed, creationTime
            FROM moz_cookies
            ORDER BY lastAccessed DESC
            """

            cursor.execute(query)
            rows = cursor.fetchall()

            for row in rows:
                host, name, value, path, expiry, isSecure, isHttpOnly, lastAccessed, creationTime = row
                cookies_data.append({
                    'browser': 'Firefox',
                    'host': host,
                    'name': name,
                    'value': value,
                    'path': path,
                    'expiry': self.firefox_timestamp_to_datetime(expiry * 1000000 if expiry else 0),
                    'isSecure': bool(isSecure),
                    'isHttpOnly': bool(isHttpOnly),
                    'lastAccessed': self.firefox_timestamp_to_datetime(lastAccessed or 0),
                    'creationTime': self.firefox_timestamp_to_datetime(creationTime or 0)
                })

            conn.close()

        except sqlite3.Error as e:
            print(f"Error reading Firefox cookies: {e}")
        finally:
            if temp_db.exists():
                temp_db.unlink()

        return cookies_data

    def extract_safari_downloads(self, safari_path):
        """Extract Safari download history."""
        downloads_data = []

        # Try to read Downloads.plist first
        downloads_plist = safari_path / "Downloads.plist"
        if downloads_plist.exists():
            try:
                import plistlib
                with open(downloads_plist, 'rb') as f:
                    plist_data = plistlib.load(f)

                if isinstance(plist_data, dict) and 'DownloadHistory' in plist_data:
                    download_history = plist_data['DownloadHistory']
                    if isinstance(download_history, list):
                        for download in download_history:
                            if isinstance(download, dict):
                                download_info = {
                                    'browser': 'Safari',
                                    'target_path': download.get('DownloadEntryPath', ''),
                                    'url': download.get('DownloadEntryURL', ''),
                                    'start_time': None,  # Safari plist doesn't store timestamps
                                    'end_time': None,
                                    'received_bytes': download.get('DownloadEntryBytesLoaded', 0),
                                    'total_bytes': download.get('DownloadEntryBytesTotal', 0),
                                    'danger_type': 0,  # Safari doesn't classify downloads this way
                                    'opened': download.get('DownloadEntryWasViewed', False)
                                }
                                downloads_data.append(download_info)
            except Exception as e:
                print(f"Error reading Safari Downloads.plist: {e}")

        # If no downloads found in plist, try to scan Downloads folder for Safari files
        # Safari doesn't always maintain detailed download history, so this is a fallback
        if not downloads_data:
            try:
                downloads_folder = Path.home() / "Downloads"
                if downloads_folder.exists():
                    # Look for files that might be Safari downloads (this is approximate)
                    # Safari doesn't mark files as "from Safari" in filesystem metadata
                    print("Note: Safari download history is limited. Scanning Downloads folder for recent files...")

                    # Get files modified in the last 30 days (reasonable forensic timeframe)
                    cutoff_time = datetime.now() - timedelta(days=30)

                    for file_path in downloads_folder.iterdir():
                        if file_path.is_file():
                            try:
                                mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                                if mtime > cutoff_time:
                                    # Basic file info (Safari doesn't store source URLs in filesystem)
                                    download_info = {
                                        'browser': 'Safari',
                                        'target_path': str(file_path),
                                        'url': '',  # Safari doesn't store source URLs in filesystem
                                        'start_time': None,
                                        'end_time': mtime,  # Approximate end time from file modification
                                        'received_bytes': file_path.stat().st_size,
                                        'total_bytes': file_path.stat().st_size,
                                        'danger_type': 0,
                                        'opened': True  # Assume downloaded files are opened
                                    }
                                    downloads_data.append(download_info)
                            except (OSError, ValueError):
                                continue

                    if downloads_data:
                        print(f"Found {len(downloads_data)} files in Downloads folder (Safari attribution approximate)")

            except Exception as e:
                print(f"Error scanning Downloads folder: {e}")

        # Sort Safari downloads chronologically (newest first) like Chrome
        if downloads_data:
            downloads_data.sort(key=lambda x: x.get('end_time') or datetime.min, reverse=True)

        return downloads_data

    def extract_safari_cookies(self, safari_path):
        """Extract Safari cookies from binary cookies file."""
        cookies_data = []

        # Safari cookies are stored in a sandboxed container
        cookies_file = Path.home() / "Library" / "Containers" / "com.apple.Safari" / "Data" / "Library" / "Cookies" / "Cookies.binarycookies"

        if not cookies_file.exists():
            print(f"Safari cookies file not found: {cookies_file}")
            return cookies_data

        try:
            with open(cookies_file, 'rb') as f:
                # Basic binary cookies parsing
                # Safari uses a custom binary format, this is a simplified parser
                data = f.read()

                # Check for magic number (binary cookies start with 'cook')
                if len(data) < 4 or data[:4] != b'cook':
                    print("Invalid Safari cookies file format")
                    return cookies_data

                # Parse page size (usually 4096)
                page_size = int.from_bytes(data[4:8], byteorder='big')

                # Parse number of pages
                num_pages = int.from_bytes(data[8:12], byteorder='big')

                print(f"Safari cookies file: {num_pages} pages, page size {page_size}")

                # For now, just report that cookies exist but don't parse the complex binary format
                # Full parsing would require detailed knowledge of Safari's binary cookie format
                cookies_data.append({
                    'browser': 'Safari',
                    'host_key': 'safari_cookies_binary',
                    'name': 'binary_cookies_file',
                    'value': f'Contains {num_pages} pages of cookie data',
                    'path': '/',
                    'expires_utc': None,
                    'is_secure': True,
                    'is_httponly': True,
                    'last_access_utc': None,
                    'creation_utc': None,
                    'has_expires': False,
                    'is_persistent': True
                })

        except (OSError, PermissionError) as e:
            print(f"Cannot access Safari cookies file: {e}")
            print("Note: Safari cookies require Full Disk Access permissions on macOS")
        except Exception as e:
            print(f"Error reading Safari cookies: {e}")

        return cookies_data

    def extract_safari_deleted_history(self, safari_path):
        """Extract deleted Safari history from tombstone records."""
        deleted_history = []

        history_db = safari_path / "History.db"
        if not history_db.exists():
            return deleted_history

        # Force WAL checkpoint first
        try:
            conn = sqlite3.connect(str(history_db))
            cursor = conn.cursor()
            cursor.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            conn.close()
        except Exception as e:
            print(f"Warning: Could not checkpoint Safari WAL for tombstones: {e}")

        temp_db = self.output_dir / "safari_tombstones_temp.db"
        try:
            shutil.copy2(history_db, temp_db)
        except (OSError, PermissionError):
            return deleted_history

        try:
            conn = sqlite3.connect(str(temp_db))
            cursor = conn.cursor()

            # Check if tombstones table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='history_tombstones'")
            if not cursor.fetchone():
                conn.close()
                return deleted_history

            # Get tombstones
            cursor.execute("SELECT id, start_time, end_time, url, generation FROM history_tombstones ORDER BY end_time DESC")
            tombstones = cursor.fetchall()

            if tombstones:
                print(f"Found {len(tombstones)} deleted Safari history records in tombstones")

            for tombstone in tombstones:
                tombstone_id, start_time, end_time, url_data, generation = tombstone

                # Create entry for deleted history
                deleted_entry = {
                    'browser': 'Safari',
                    'title': '[DELETED RECORD - See Tombstones]',
                    'url': f'[Deleted Safari Record ID: {tombstone_id}]',
                    'visit_count': 0,
                    'visit_time': self.safari_timestamp_to_datetime(end_time or 0),
                    'tombstone_id': tombstone_id,
                    'generation': generation,
                    'deletion_time': self.safari_timestamp_to_datetime(end_time or 0) if end_time else None
                }

                # Try to extract URL from binary data if possible
                if isinstance(url_data, bytes) and url_data:
                    try:
                        # Safari stores URLs in a specific binary format
                        # Try multiple approaches to extract meaningful data

                        # 1. Try UTF-8 decoding
                        data_str = url_data.decode('utf-8', errors='ignore')

                        # 2. Look for URL patterns
                        import re
                        urls = re.findall(r'https?://[^\s\"\'<>]+', data_str)
                        if urls:
                            deleted_entry['url'] = f'[Recovered Deleted URL] {urls[0]}'
                            deleted_entry['title'] = '[Recovered Deleted URL]'
                            deleted_entry['recovery_status'] = 'URL partially recovered from tombstone'
                        else:
                            # 3. Try to find domain-like patterns
                            domains = re.findall(r'\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?\b', data_str)
                            if domains:
                                deleted_entry['url'] = f'[Recovered Domain] {domains[0]}'
                                deleted_entry['title'] = '[Recovered Domain]'
                                deleted_entry['recovery_status'] = 'Domain partially recovered from tombstone'

                            # 4. Show hex dump for forensic analysis
                            else:
                                hex_dump = url_data[:50].hex()
                                deleted_entry['url'] = f'[Encrypted Data] {hex_dump}...'
                                deleted_entry['title'] = '[Encrypted Tombstone Data]'
                                deleted_entry['recovery_status'] = f'Binary data ({len(url_data)} bytes) - requires advanced forensics'

                    except Exception as e:
                        deleted_entry['recovery_status'] = f'Error parsing tombstone: {str(e)}'

                deleted_history.append(deleted_entry)

            conn.close()

        except sqlite3.Error as e:
            print(f"Error reading Safari tombstones: {e}")
        except Exception as e:
            print(f"Unexpected error reading Safari tombstones: {e}")
        finally:
            if temp_db.exists():
                temp_db.unlink()

        return deleted_history

    def extract_chrome_deleted_history(self, profile_path):
        """Attempt to recover deleted Chrome history using basic SQLite forensics."""
        deleted_history = []

        history_db = profile_path / "History"
        if not history_db.exists():
            return deleted_history

        temp_db = self.output_dir / "chrome_deleted_temp.db"
        try:
            shutil.copy2(history_db, temp_db)
        except (OSError, PermissionError):
            return deleted_history

        try:
            conn = sqlite3.connect(str(temp_db))
            cursor = conn.cursor()

            # Check for free pages (unallocated space where deleted data might be)
            cursor.execute('PRAGMA freelist_count')
            freelist_count = cursor.fetchone()[0]

            # Get page size
            cursor.execute('PRAGMA page_size')
            page_size = cursor.fetchone()[0]

            free_space_bytes = freelist_count * page_size

            if freelist_count > 0:
                print(f"Chrome History database has {freelist_count} free pages ({free_space_bytes:,} bytes)")
                print("This may contain recoverable deleted history records")

                # Create a summary entry about potential deleted data
                deleted_entry = {
                    'browser': 'Chrome',
                    'title': '[POTENTIAL DELETED RECORDS - Forensic Analysis Required]',
                    'url': f'[Chrome Database Free Space: {free_space_bytes:,} bytes in {freelist_count} pages]',
                    'visit_count': 0,
                    'visit_time': None,  # Unknown deletion time
                    'free_pages': freelist_count,
                    'free_space_bytes': free_space_bytes,
                    'recovery_status': 'Potential recovery - requires specialized SQLite forensics tools'
                }
                deleted_history.append(deleted_entry)

            # Check for journal file (rollback journal)
            journal_file = profile_path / "History-journal"
            if journal_file.exists():
                journal_size = journal_file.stat().st_size
                print(f"Found Chrome journal file: {journal_size:,} bytes")

                journal_entry = {
                    'browser': 'Chrome',
                    'title': '[JOURNAL FILE - May Contain Deleted Records]',
                    'url': f'[Chrome Journal File: {journal_size:,} bytes]',
                    'visit_count': 0,
                    'visit_time': None,
                    'journal_size': journal_size,
                    'recovery_status': 'Journal file present - may contain uncommitted deleted transactions'
                }
                deleted_history.append(journal_entry)

            conn.close()

        except sqlite3.Error as e:
            print(f"Error analyzing Chrome database for deleted records: {e}")
        except Exception as e:
            print(f"Unexpected error in Chrome deleted history analysis: {e}")
        finally:
            if temp_db.exists():
                temp_db.unlink()

        return deleted_history

    def extract_safari_history(self, safari_path):
        """Extract Safari browsing history."""
        history_db = safari_path / "History.db"
        if not history_db.exists():
            print(f"Safari History.db not found: {history_db}")
            print("Note: Safari history may require Full Disk Access permissions on macOS")
            return []

        # Force WAL checkpoint to ensure recent history is written to main DB
        try:
            conn = sqlite3.connect(str(history_db))
            cursor = conn.cursor()
            cursor.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            conn.close()
            print("Safari WAL checkpoint completed")
        except Exception as e:
            print(f"Warning: Could not checkpoint Safari WAL: {e}")

        temp_db = self.output_dir / "safari_history_temp.db"
        try:
            shutil.copy2(history_db, temp_db)
        except (OSError, PermissionError) as e:
            print(f"Cannot access Safari history database: {e}")
            print("Note: Safari files are protected on macOS. To access Safari data:")
            print("  1. Go to System Settings > Privacy & Security > Full Disk Access")
            print("  2. Add Terminal (or your Python IDE) to the list")
            print("  3. Restart your terminal/Python environment")
            return []
        except Exception as e:
            print(f"Unexpected error accessing Safari history: {e}")
            return []

        history_data = []
        try:
            conn = sqlite3.connect(str(temp_db))
            cursor = conn.cursor()

            # Check if required tables exist
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('history_items', 'history_visits')")
            tables = [row[0] for row in cursor.fetchall()]

            if 'history_items' not in tables:
                print("Safari history_items table not found")
                conn.close()
                return []

            if 'history_visits' not in tables:
                print("Safari history_visits table not found")
                conn.close()
                return []

            # Check available columns in history_items table
            cursor.execute("PRAGMA table_info(history_items)")
            history_items_columns = {col[1]: col[0] for col in cursor.fetchall()}

            # Check available columns in history_visits table
            cursor.execute("PRAGMA table_info(history_visits)")
            history_visits_columns = {col[1]: col[0] for col in cursor.fetchall()}

            # Build query based on available columns
            select_columns = ["history_items.url"]
            # Safari doesn't store titles in history database
            if 'visit_time' in history_visits_columns:
                select_columns.append("history_visits.visit_time")
            if 'visit_count' in history_items_columns:
                select_columns.append("history_items.visit_count")

            if len(select_columns) < 2:  # Need at least URL and one other field
                print("Insufficient columns found in Safari history tables")
                conn.close()
                return []

            query = f"""
            SELECT {', '.join(select_columns)}
            FROM history_items
            LEFT JOIN history_visits ON history_items.id = history_visits.history_item
            ORDER BY history_visits.visit_time DESC
            """

            cursor.execute(query)
            rows = cursor.fetchall()

            for row in rows:
                if len(row) >= len(select_columns):
                    history_entry = {'browser': 'Safari'}

                    col_idx = 0
                    if 'url' in history_items_columns:
                        history_entry['url'] = row[col_idx] or ''
                        col_idx += 1

                    # Safari doesn't store titles in history database - use domain as pseudo-title
                    try:
                        from urllib.parse import urlparse
                        parsed_url = urlparse(history_entry['url'])
                        domain = parsed_url.netloc
                        if domain.startswith('www.'):
                            domain = domain[4:]
                        history_entry['title'] = f"[{domain}]" if domain else "[No title available]"
                    except:
                        history_entry['title'] = "[No title available]"

                    if 'visit_time' in history_visits_columns and col_idx < len(row):
                        visit_time_raw = row[col_idx]
                        # Convert to float if it's a string representation of a number
                        try:
                            if isinstance(visit_time_raw, str):
                                visit_time_raw = float(visit_time_raw)
                            elif visit_time_raw is None:
                                visit_time_raw = 0
                            history_entry['visit_time'] = self.safari_timestamp_to_datetime(visit_time_raw)
                        except (ValueError, TypeError):
                            history_entry['visit_time'] = None
                        col_idx += 1
                    else:
                        history_entry['visit_time'] = None

                    if 'visit_count' in history_items_columns and col_idx < len(row):
                        history_entry['visit_count'] = row[col_idx] or 0
                    else:
                        history_entry['visit_count'] = 0

                    history_data.append(history_entry)

            conn.close()

        except sqlite3.Error as e:
            print(f"Error reading Safari history: {e}")
        except Exception as e:
            print(f"Unexpected error reading Safari history: {e}")
        finally:
            if temp_db.exists():
                temp_db.unlink()

        # Try to extract deleted history from tombstones
        deleted_history = self.extract_safari_deleted_history(safari_path)
        history_data.extend(deleted_history)

        return history_data

    def extract_all_browsers(self, custom_paths=None):
        """Extract artifacts from all available browsers."""
        browser_paths = self.get_browser_paths()
        if custom_paths:
            browser_paths.update(custom_paths)

        all_data = {
            'history': [],
            'downloads': [],
            'cookies': []
        }

        # Extract Chrome data
        chrome_path = browser_paths.get('chrome')
        if chrome_path and chrome_path.exists():
            print(f"Extracting Chrome data from: {chrome_path}")
            try:
                all_data['history'].extend(self.extract_chrome_history(chrome_path))
                all_data['downloads'].extend(self.extract_chrome_downloads(chrome_path))
                all_data['cookies'].extend(self.extract_chrome_cookies(chrome_path))
            except Exception as e:
                print(f"Error extracting Chrome data: {e}")
        else:
            print("Chrome profile not found, skipping Chrome extraction")

        # Extract Firefox data
        firefox_base = browser_paths.get('firefox')
        if firefox_base and firefox_base.exists():
            # Firefox has profile directories, find the default one
            try:
                profile_dirs = [d for d in firefox_base.iterdir() if d.is_dir() and not d.name.endswith('.default')]
                if not profile_dirs:
                    profile_dirs = [d for d in firefox_base.iterdir() if d.is_dir()]

                if profile_dirs:
                    firefox_path = profile_dirs[0]  # Use first profile
                    print(f"Extracting Firefox data from: {firefox_path}")
                    all_data['history'].extend(self.extract_firefox_history(firefox_path))
                    all_data['cookies'].extend(self.extract_firefox_cookies(firefox_path))
                else:
                    print("No Firefox profiles found")
            except Exception as e:
                print(f"Error extracting Firefox data: {e}")
        else:
            print("Firefox profile not found, skipping Firefox extraction")

        # Extract Safari data (macOS only)
        safari_path = browser_paths.get('safari')
        if safari_path and safari_path.exists():
            print(f"Extracting Safari data from: {safari_path}")
            try:
                all_data['history'].extend(self.extract_safari_history(safari_path))
                all_data['downloads'].extend(self.extract_safari_downloads(safari_path))
                all_data['cookies'].extend(self.extract_safari_cookies(safari_path))
            except Exception as e:
                print(f"Error extracting Safari data: {e}")
        else:
            print("Safari profile not found, skipping Safari extraction")

        return all_data

    def save_to_csv(self, data, filename, data_type):
        """Save extracted data to CSV file."""
        if not data:
            print(f"No {data_type} data to save")
            return

        output_file = self.output_dir / f"{filename}.csv"

        # Get all unique keys from the data
        fieldnames = set()
        for item in data:
            fieldnames.update(item.keys())

        fieldnames = sorted(fieldnames)

        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for item in data:
                # Convert datetime objects to strings
                row = {}
                for key, value in item.items():
                    if isinstance(value, datetime):
                        row[key] = value.isoformat() if value else ''
                    else:
                        row[key] = value
                writer.writerow(row)

        print(f"Saved {len(data)} {data_type} records to {output_file}")

    def save_to_csv_basic_columns(self, data, filename, data_type):
        """Save data to CSV with only basic columns (for regular history)."""
        if not data:
            print(f"No {data_type} data to save")
            return

        output_file = self.output_dir / f"{filename}.csv"

        # Use only basic columns for regular history
        basic_fieldnames = ['browser', 'title', 'url', 'visit_count', 'visit_time']

        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=basic_fieldnames)
            writer.writeheader()
            for item in data:
                # Convert datetime objects to strings and only include basic fields
                row = {}
                for key in basic_fieldnames:
                    if key in item:
                        if isinstance(item[key], datetime):
                            row[key] = item[key].isoformat() if item[key] else ''
                        else:
                            row[key] = item[key]
                writer.writerow(row)

        print(f"Saved {len(data)} {data_type} records to {output_file}")

    def save_all_data(self, all_data):
        """Save all extracted data to CSV files."""
        # History saving is now handled in the separation logic above
        self.save_to_csv(all_data['downloads'], 'browser_downloads', 'downloads')
        self.save_to_csv(all_data['cookies'], 'browser_cookies', 'cookies')

        # Separate regular history from deleted/forensic records
        regular_history = []
        deleted_history = []

        for item in all_data['history']:
            if (item.get('title', '').startswith('[DELETED') or
                item.get('title', '').startswith('[Recovered') or
                item.get('title', '').startswith('[Encrypted') or
                item.get('title', '').startswith('[JOURNAL') or
                item.get('title', '').startswith('[POTENTIAL')):
                deleted_history.append(item)
            else:
                regular_history.append(item)

        # Save regular history with basic columns only
        self.save_to_csv_basic_columns(regular_history, 'browser_history', 'history')

        # Save deleted history with all forensic columns
        if deleted_history:
            self.save_to_csv(deleted_history, 'deleted_browser_history', 'deleted')

            print(f"\n🔍 DELETED HISTORY FOUND:")
            print(f"   📁 {len(deleted_history)} deleted records saved to deleted_browser_history.csv")
            safari_deleted = [r for r in deleted_history if r.get('browser') == 'Safari' and 'tombstone_id' in r]
            chrome_deleted = [r for r in deleted_history if r.get('browser') == 'Chrome']

            if safari_deleted:
                print(f"   🧭 {len(safari_deleted)} Safari deleted history records (timestamps + encrypted URLs)")
            if chrome_deleted:
                print(f"   📊 {len(chrome_deleted)} Chrome deleted history artifacts (journal files, free space)")

        # Save summary
        summary = {
            'extraction_timestamp': datetime.now().isoformat(),
            'total_regular_history_records': len(regular_history),
            'total_deleted_history_records': len(deleted_history),
            'total_download_records': len(all_data['downloads']),
            'total_cookie_records': len(all_data['cookies']),
            'browsers_found': list(set([item['browser'] for item in all_data['history']] +
                                     [item['browser'] for item in all_data['downloads']] +
                                     [item['browser'] for item in all_data['cookies']]))
        }

        summary_file = self.output_dir / 'extraction_summary.json'
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)

        print(f"Extraction summary saved to {summary_file}")

def main():
    parser = argparse.ArgumentParser(description='Extract browser artifacts for forensic analysis')
    parser.add_argument('-o', '--output', default='data/raw',
                       help='Output directory for extracted data (default: data/raw)')
    parser.add_argument('-b', '--browsers', nargs='+',
                       choices=['chrome', 'firefox', 'safari', 'edge'],
                       help='Specific browsers to extract from')
    parser.add_argument('-p', '--paths', nargs='+',
                       help='Custom paths to browser profiles (format: browser:path)')

    args = parser.parse_args()

    extractor = BrowserExtractor(args.output)

    # Parse custom paths
    custom_paths = {}
    if args.paths:
        for path_arg in args.paths:
            if ':' in path_arg:
                browser, path = path_arg.split(':', 1)
                custom_paths[browser] = Path(path)

    print("Starting browser artifact extraction...")
    print(f"Output directory: {extractor.output_dir}")
    print(f"Operating System: {platform.system()}")

    all_data = extractor.extract_all_browsers(custom_paths)
    extractor.save_all_data(all_data)

    print("\nExtraction completed!")
    print(f"History records: {len(all_data['history'])}")
    print(f"Download records: {len(all_data['downloads'])}")
    print(f"Cookie records: {len(all_data['cookies'])}")

if __name__ == "__main__":
    main()
