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
import logging
from datetime import datetime, timedelta
from pathlib import Path
import plistlib
import struct
import lz4.block  # For Firefox session file decompression

# Import our Firefox forensics tools
try:
    import sys
    sys.path.append(str(Path(__file__).parent.parent))
    from tools.firefox_forensics.firefox_forensics import FirefoxForensics
    from tools.firefox_forensics.advanced_recovery import AdvancedFirefoxRecovery
    FIREFOX_FORENSICS_AVAILABLE = True
except ImportError as e:
    FIREFOX_FORENSICS_AVAILABLE = False
    logging.warning(f"Firefox forensics tools not available: {e}. Some recovery features will be limited.")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class BrowserExtractor:
    """Main class for extracting browser artifacts."""

    def __init__(self, output_dir="../data/raw"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.system = platform.system().lower()
        self.timestamp_base = {
            'chrome': 11644473600000000,  # Chrome uses microseconds since 1601-01-01
            'firefox': 0,  # Firefox uses microseconds since 1970-01-01 (Unix timestamp * 1000000)
            'safari': 978307200  # Safari uses seconds since 2001-01-01
        }

    def get_firefox_profile_path(self):
        """Get the default Firefox profile path by reading profiles.ini."""
        possible_locations = [
            Path.home() / ".mozilla" / "firefox",  # Standard Linux
            Path.home() / "snap" / "firefox" / "common" / ".mozilla" / "firefox",  # Ubuntu Snap
            Path.home() / "Library" / "Application Support" / "Firefox" / "Profiles",  # macOS
            Path(os.environ.get('APPDATA', '')) / "Mozilla" / "Firefox" / "Profiles"  # Windows
        ]

        for location in possible_locations:
            profiles_ini = location / "profiles.ini"
            if profiles_ini.exists():
                try:
                    # Read profiles.ini
                    with open(profiles_ini, 'r') as f:
                        lines = f.readlines()
                    
                    # Parse for default profile
                    current_section = None
                    profile_path = None
                    is_relative = None
                    
                    for line in lines:
                        line = line.strip()
                        if line.startswith('['):
                            current_section = line[1:-1]
                        elif current_section and current_section.startswith('Profile'):
                            if line.startswith('Path='):
                                profile_path = line[5:]
                            elif line.startswith('IsRelative='):
                                is_relative = line[11:] == '1'
                            elif line.startswith('Default=1'):
                                if profile_path:
                                    if is_relative:
                                        return location / profile_path
                                    else:
                                        return Path(profile_path)
                    
                    # If no default profile found but we have a path, use the first one
                    if profile_path:
                        if is_relative:
                            return location / profile_path
                        else:
                            return Path(profile_path)
                except Exception as e:
                    print(f"Warning: Error reading Firefox profiles.ini: {e}")
                    continue
        
        return None

    def get_browser_paths(self):
        """Get default browser profile paths for different operating systems."""
        paths = {}

        if self.system == "windows":
            paths = {
                'chrome': Path(os.environ.get('LOCALAPPDATA', '')) / "Google" / "Chrome" / "User Data" / "Default",
                'edge': Path(os.environ.get('LOCALAPPDATA', '')) / "Microsoft" / "Edge" / "User Data" / "Default",
                'safari': None  # Safari not available on Windows
            }
        elif self.system == "darwin":  # macOS
            paths = {
                'chrome': Path.home() / "Library" / "Application Support" / "Google" / "Chrome" / "Default",
                'safari': Path.home() / "Library" / "Safari",
                'edge': None  # Edge path on macOS if installed
            }
        elif self.system == "linux":
            paths = {
                'chrome': Path.home() / ".config" / "google-chrome" / "Default",
                'safari': None,  # Safari not available on Linux
                'edge': None
            }

        # Add Firefox path from profiles.ini
        firefox_path = self.get_firefox_profile_path()
        paths['firefox'] = firefox_path if firefox_path else Path.home() / ".mozilla" / "firefox"

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
        if timestamp is None or timestamp == 0:
            return None
        try:
            # Firefox uses microseconds since 1970-01-01
            # Handle both integer and float timestamps
            if isinstance(timestamp, float):
                pass  # Already a float
            elif isinstance(timestamp, int):
                timestamp = float(timestamp)
            else:
                timestamp = float(timestamp)

            # Sanity check - ignore timestamps too far in the future
            max_year = 2100  # Reasonable maximum year
            max_timestamp = (datetime(max_year, 1, 1) - datetime(1970, 1, 1)).total_seconds() * 1000000
            if timestamp > max_timestamp:
                return None

            return datetime.fromtimestamp(timestamp / 1000000)
        except (ValueError, TypeError, OSError) as e:
            print(f"Warning: Invalid Firefox timestamp: {timestamp} ({str(e)})")
            return None

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

    def extract_firefox_session_history(self, profile_path):
        """Extract history from Firefox session backups."""
        deleted_history = []
        session_dir = profile_path / "sessionstore-backups"
        
        if not session_dir.exists():
            return deleted_history

        # Look for session backup files
        backup_files = [
            session_dir / "recovery.jsonlz4",
            session_dir / "recovery.baklz4",
            session_dir / "previous.jsonlz4"
        ]

        current_urls = set()  # Track URLs we've already seen
        
        for backup_file in backup_files:
            if not backup_file.exists():
                continue

            try:
                # Read LZ4 compressed session file
                with open(backup_file, 'rb') as f:
                    # Skip Mozilla LZ4 header (8 bytes "mozLz40\0" + 4 bytes size)
                    header = f.read(8)
                    if header != b'mozLz40\0':
                        print(f"Warning: Invalid header in {backup_file}: {header}")
                        continue
                    
                    expected_size = struct.unpack('<I', f.read(4))[0]
                    compressed_data = f.read()
                    
                    try:
                        # Decompress data with explicit size
                        json_data = lz4.block.decompress(compressed_data, uncompressed_size=expected_size)
                        if len(json_data) != expected_size:
                            print(f"Warning: Decompressed size mismatch in {backup_file}")
                        
                        # Parse JSON
                        session_data = json.loads(json_data)
                        
                        # Extract URLs from windows and tabs
                        for window in session_data.get('windows', []):
                            for tab in window.get('tabs', []):
                                entries = tab.get('entries', [])
                                for entry in entries:
                                    url = entry.get('url', '')
                                    title = entry.get('title', '')
                                    last_accessed = entry.get('lastAccessed', 0)  # Timestamp in ms since epoch
                                    
                                    # Skip if we've seen this URL or it's in current history
                                    if url in current_urls or not url or url.startswith('about:'):
                                        continue
                                    current_urls.add(url)
                                    
                                    # Convert timestamp from ms to microseconds
                                    visit_time = last_accessed * 1000 if last_accessed else 0
                                    
                                    # Create a complete record with all required fields
                                    record = {
                                        'browser': 'Firefox',
                                        'title': f'[RECOVERED FROM SESSION] {title}',
                                        'url': url,
                                        'visit_count': 1,
                                        'visit_time': self.firefox_timestamp_to_datetime(visit_time),
                                        'tombstone_id': None,
                                        'generation': None,
                                        'deletion_time': datetime.now().isoformat(),
                                        'free_pages': None,
                                        'free_space_bytes': None,
                                        'journal_size': None,
                                        'recovery_status': f'Recovered from {backup_file.name}'
                                    }
                                    
                                    # Only add if we have a valid URL and title
                                    if url and title:
                                        print(f"Found deleted history: {url}")
                                        # Add to deleted history list
                                        deleted_history.append(record)
                                        # Print record for debugging
                                        print(f"Record: {record}")
                    except lz4.block.LZ4BlockError as e:
                        print(f"LZ4 decompression error in {backup_file}: {e}")
                        continue
                    except json.JSONDecodeError as e:
                        print(f"JSON parsing error in {backup_file}: {e}")
                        continue
                
                print(f"Processed session backup: {backup_file}")
                
            except Exception as e:
                print(f"Error reading session backup {backup_file}: {e}")
                continue

        return deleted_history

    def extract_firefox_history(self, profile_path):
        """Extract Firefox browsing history using advanced forensics tools if available."""
        history_data = []
        
        # Try using advanced forensics tools first
        if FIREFOX_FORENSICS_AVAILABLE:
            try:
                forensics = FirefoxForensics(profile_path)
                
                # Get regular history
                places_db = profile_path / "places.sqlite"
                if places_db.exists():
                    places_analysis = forensics.analyze_places_database()
                    if places_analysis and 'deleted_entries' in places_analysis:
                        for entry in places_analysis['deleted_entries']:
                            if entry.get('url') and entry.get('title'):
                                history_data.append({
                                    'browser': 'Firefox',
                                    'url': entry['url'],
                                    'title': entry['title'],
                                    'visit_count': 1,  # Assume at least one visit
                                    'visit_time': entry.get('visit_date'),
                                    'recovery_method': 'forensics_places'
                                })
                
                # Get session history
                session_history = forensics.parse_session_data()
                for entry in session_history:
                    if entry.get('url') and entry.get('title'):
                        history_data.append({
                            'browser': 'Firefox',
                            'url': entry['url'],
                            'title': entry['title'],
                            'visit_count': 1,
                            'visit_time': datetime.fromtimestamp(entry['timestamp'] / 1000) if entry.get('timestamp') else None,
                            'recovery_method': 'forensics_session'
                        })
                
                logging.info(f"Recovered {len(history_data)} entries using forensics tools")
                
            except Exception as e:
                logging.error(f"Error using forensics tools: {e}")
                # Fall back to basic extraction
                logging.info("Falling back to basic extraction method")
        
        # If forensics failed or not available, use basic extraction
        if not history_data:
            places_db = profile_path / "places.sqlite"
            if not places_db.exists():
                logging.warning(f"Firefox places.sqlite not found: {places_db}")
                return []

            temp_db = self.output_dir / "firefox_places_temp.db"
            shutil.copy2(places_db, temp_db)

            try:
                conn = sqlite3.connect(str(temp_db))
                cursor = conn.cursor()

                # Check if required tables exist
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('moz_places', 'moz_historyvisits')")
                tables = [row[0] for row in cursor.fetchall()]

                if 'moz_places' not in tables:
                    logging.warning("Firefox places table not found")
                    conn.close()
                    return []

                if 'moz_historyvisits' not in tables:
                    logging.warning("Firefox history visits table not found")
                    conn.close()
                    return []

                # Get the latest history entries with their visit dates
                # Note: Firefox stores visit_date in microseconds since 1970-01-01
                query = """
                SELECT p.url, p.title, p.visit_count, h.visit_date
                FROM moz_places p
                JOIN moz_historyvisits h ON p.id = h.place_id
                WHERE h.visit_date IS NOT NULL
                  AND h.visit_date > strftime('%s', 'now', '-7 days') * 1000000  -- Last week only
                  AND h.visit_type IN (1, 2)  -- Only direct navigation (1) and link clicks (2)
                ORDER BY h.visit_date DESC
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
                        'visit_time': self.firefox_timestamp_to_datetime(visit_date or 0),
                        'recovery_method': 'standard'
                    })

                conn.close()
            except sqlite3.Error as e:
                logging.error(f"Error reading Firefox history: {e}")
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
        """Extract Safari cookies from SQLite database."""
        cookies_data = []

        # Try SQLite database first (newer Safari versions)
        cookies_db = Path.home() / "Library" / "Containers" / "com.apple.Safari" / "Data" / "Library" / "Cookies" / "Cookies.db"
        
        if cookies_db.exists():
            print("Found Safari SQLite cookies database")
            temp_db = self.output_dir / "safari_cookies_temp.db"
            
            try:
                shutil.copy2(cookies_db, temp_db)
                conn = sqlite3.connect(str(temp_db))
                cursor = conn.cursor()

                query = """
                SELECT 
                    host_key,
                    name,
                    value,
                    path,
                    expires_utc,
                    is_secure,
                    is_httponly,
                    last_access_utc,
                    creation_utc
                FROM cookies
                ORDER BY creation_utc DESC
                """

                cursor.execute(query)
                rows = cursor.fetchall()

                for row in rows:
                    host_key, name, value, path, expires, secure, httponly, last_access, creation = row
                    cookie = {
                        'browser': 'Safari',
                        'host_key': host_key,
                        'name': name,
                        'value': value,
                        'path': path or '/',
                        'expires_utc': self.safari_timestamp_to_datetime(expires) if expires else None,
                        'is_secure': bool(secure),
                        'is_httponly': bool(httponly),
                        'last_access_utc': self.safari_timestamp_to_datetime(last_access) if last_access else None,
                        'creation_utc': self.safari_timestamp_to_datetime(creation) if creation else None
                    }
                    cookies_data.append(cookie)

                conn.close()

            except sqlite3.Error as e:
                print(f"SQLite error reading Safari cookies: {e}")
            except Exception as e:
                print(f"Error reading Safari cookies database: {e}")
            finally:
                if temp_db.exists():
                    temp_db.unlink()

        # If no SQLite database or no cookies found, try binary cookies file
        if not cookies_data:
            binary_cookies = Path.home() / "Library" / "Cookies" / "Cookies.binarycookies"
            
            if binary_cookies.exists():
                try:
                    with open(binary_cookies, 'rb') as f:
                        data = f.read()
                        
                        if len(data) < 4 or data[:4] != b'cook':
                            print("Invalid Safari binary cookies format")
                            return cookies_data

                        # Parse cookie file structure
                        page_size = int.from_bytes(data[4:8], byteorder='big')
                        num_pages = int.from_bytes(data[8:12], byteorder='big')
                        
                        # Parse each page
                        offset = 12
                        for page in range(num_pages):
                            try:
                                # Read page header
                                if offset + 4 > len(data): break
                                num_cookies = int.from_bytes(data[offset:offset+4], byteorder='little')
                                offset += 4

                                # Read cookies in this page
                                for _ in range(num_cookies):
                                    try:
                                        # Find null-terminated strings
                                        def read_string():
                                            nonlocal offset
                                            start = offset
                                            while offset < len(data) and data[offset] != 0:
                                                offset += 1
                                            s = data[start:offset].decode('utf-8', errors='ignore')
                                            offset += 1  # skip null
                                            return s

                                        # Read cookie fields
                                        cookie = {
                                            'browser': 'Safari',
                                            'host_key': read_string(),
                                            'name': read_string(),
                                            'path': read_string(),
                                            'value': read_string(),
                                            'is_secure': True,  # Default values
                                            'is_httponly': True,
                                            'creation_utc': None,
                                            'expires_utc': None,
                                            'last_access_utc': None
                                        }
                                        
                                        # Skip binary flags and timestamps (12 bytes)
                                        offset += 12
                                        
                                        cookies_data.append(cookie)

                                    except Exception as e:
                                        print(f"Error parsing cookie in page {page}: {e}")
                                        continue

                            except Exception as e:
                                print(f"Error parsing page {page}: {e}")
                                continue

                        print(f"Extracted {len(cookies_data)} cookies from binary cookies file")

                except (OSError, PermissionError) as e:
                    print(f"Cannot access Safari binary cookies file: {e}")
                except Exception as e:
                    print(f"Error reading Safari binary cookies: {e}")

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
                logging.info(f"Found {len(tombstones)} deleted Safari history records in tombstones")

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
            'cookies': [],
            'deleted_history': []  # Initialize deleted_history list
        }
        print("Initialized all_data with empty lists")

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
        firefox_path = custom_paths.get('firefox') if custom_paths else self.get_firefox_profile_path()
        if firefox_path and firefox_path.exists():
            try:
                logging.info(f"Extracting Firefox data from: {firefox_path}")
                
                # Initialize advanced forensics if available
                forensics_data = None
                if FIREFOX_FORENSICS_AVAILABLE:
                    try:
                        # Use advanced recovery tool
                        advanced_recovery = AdvancedFirefoxRecovery(firefox_path)
                        forensics_data = advanced_recovery.recover_all()
                        logging.info(f"Recovered {len(forensics_data)} entries using advanced forensics")
                    except Exception as e:
                        logging.error(f"Error using advanced forensics tools: {e}")
                        # Fallback to basic forensics
                        try:
                            forensics = FirefoxForensics(firefox_path)
                            forensics_data = forensics.get_all_deleted_history()
                            logging.info(f"Recovered {len(forensics_data)} entries using basic forensics")
                        except Exception as e2:
                            logging.error(f"Error using basic forensics tools: {e2}")
                
                # Get regular history
                regular_history = self.extract_firefox_history(firefox_path)
                all_data['history'].extend(regular_history)
                
                # Process forensics data if available
                if forensics_data:
                    current_urls = {item['url'] for item in regular_history}
                    for item in forensics_data:
                        if item['url'] not in current_urls and not item['url'].startswith('about:'):
                            forensic_entry = {
                                'browser': 'Firefox',
                                'title': item.get('title', '[Recovered Entry]'),
                                'url': item['url'],
                                'visit_count': 1,
                                'visit_time': None,  # Advanced recovery doesn't provide timestamps
                                'recovery_method': item.get('recovery_method', 'advanced_forensics'),
                                'source': 'advanced_recovery_tool'
                            }
                            all_data['deleted_history'].append(forensic_entry)
                
                # Get session history as backup (only if advanced recovery didn't work)
                if not forensics_data:
                    session_history = self.extract_firefox_session_history(firefox_path)
                    if session_history:
                        current_urls = {item['url'] for item in regular_history + all_data['deleted_history']}
                        for item in session_history:
                            if item['url'] not in current_urls and not item['url'].startswith('about:'):
                                item['recovery_method'] = 'session_backup'
                                all_data['deleted_history'].append(item)
                
                # Get cookies
                all_data['cookies'].extend(self.extract_firefox_cookies(firefox_path))
                
                # Log recovery statistics
                logging.info(f"Firefox data recovery complete:")
                logging.info(f"- Regular history entries: {len(regular_history)}")
                logging.info(f"- Deleted history entries: {len(all_data['deleted_history'])}")
                logging.info(f"- Cookie entries: {len(all_data['cookies'])}")
                
            except Exception as e:
                logging.error(f"Error extracting Firefox data: {e}")
        else:
            logging.warning("Firefox profile not found, skipping Firefox extraction")

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

    def save_to_csv(self, data, filename, data_type, expected_fields=None):
        """Save extracted data to CSV file."""
        output_file = self.output_dir / f"{filename}.csv"

        # Ensure output directory exists
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Determine fieldnames
        if expected_fields:
            fieldnames = expected_fields
        else:
            if data_type == 'downloads':
                fieldnames = ['browser', 'target_path', 'url', 'start_time', 'end_time', 'received_bytes', 'total_bytes', 'danger_type', 'opened']
            elif data_type == 'cookies':
                fieldnames = ['browser', 'host_key', 'name', 'value', 'path', 'expires_utc', 'is_secure', 'is_httponly', 'last_access_utc', 'creation_utc']
            elif data_type == 'deleted':
                fieldnames = ['browser', 'title', 'url', 'visit_count', 'visit_time', 'tombstone_id', 'generation', 
                            'deletion_time', 'free_pages', 'free_space_bytes', 'journal_size', 'recovery_status', 
                            'recovery_method', 'source']
            else:
                fieldnames = ['browser', 'title', 'url', 'visit_count', 'visit_time', 'recovery_method']

        # Write data
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            if data:
                for item in data:
                    # Convert datetime objects to strings and ensure all fields exist
                    row = {}
                    for field in fieldnames:
                        value = item.get(field)
                        if isinstance(value, datetime):
                            row[field] = value.isoformat() if value else ''
                        else:
                            row[field] = value if value is not None else ''
                    writer.writerow(row)

        if data:
            print(f"Saved {len(data)} {data_type} records to {output_file}")
        else:
            print(f"Created empty {data_type} file: {output_file}")

    def save_to_csv_basic_columns(self, data, filename, data_type):
        """Save data to CSV with only basic columns (for regular history)."""
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

        if data:
            print(f"Saved {len(data)} {data_type} records to {output_file}")
        else:
            print(f"Created empty {data_type} file: {output_file}")

    def save_all_data(self, all_data):
        """Save all extracted data to CSV files."""
        # Save downloads and cookies
        self.save_to_csv(all_data['downloads'], 'browser_downloads', 'downloads')
        self.save_to_csv(all_data['cookies'], 'browser_cookies', 'cookies')

        # Save regular history with basic columns
        self.save_to_csv_basic_columns(all_data['history'], 'browser_history', 'history')

        # Save deleted history with all forensic columns (always create file)
        deleted_fields = ['browser', 'title', 'url', 'visit_count', 'visit_time', 'tombstone_id', 'generation', 'deletion_time', 'free_pages', 'free_space_bytes', 'journal_size', 'recovery_status']
        deleted_history = all_data.get('deleted_history', [])
        
        # Ensure all fields exist in each record
        for record in deleted_history:
            for field in deleted_fields:
                if field not in record:
                    record[field] = None
        
        # Save deleted history
        self.save_to_csv(deleted_history, 'deleted_browser_history', 'deleted', expected_fields=deleted_fields)

        if deleted_history:
            print(f"\n🔍 DELETED HISTORY FOUND:")
            print(f"   📁 {len(deleted_history)} deleted records saved to deleted_browser_history.csv")
            
            # Group by type
            firefox_session = [r for r in deleted_history if r.get('browser') == 'Firefox' and 'recovery_status' in r]
            safari_deleted = [r for r in deleted_history if r.get('browser') == 'Safari' and 'tombstone_id' in r]
            chrome_deleted = [r for r in deleted_history if r.get('browser') == 'Chrome']

            if firefox_session:
                print(f"   🦊 {len(firefox_session)} Firefox session records recovered")
            if safari_deleted:
                print(f"   🧭 {len(safari_deleted)} Safari deleted history records (timestamps + encrypted URLs)")
            if chrome_deleted:
                print(f"   📊 {len(chrome_deleted)} Chrome deleted history artifacts (journal files, free space)")

        # Save summary
        summary = {
            'extraction_timestamp': datetime.now().isoformat(),
            'total_regular_history_records': len(all_data['history']),
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
    parser.add_argument('-o', '--output', default='../data/raw',
                       help='Output directory for extracted data (default: ../data/raw)')
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
