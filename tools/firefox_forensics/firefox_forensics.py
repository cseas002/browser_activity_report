#!/usr/bin/env python3
"""
Firefox Forensics Integration Module
Integrates various Firefox forensics tools and provides a Python interface
"""

import json
import subprocess
import logging
import struct
import lz4.block
from pathlib import Path
import sqlite3
import shutil
import tempfile

class FirefoxForensics:
    def __init__(self, profile_path=None):
        self.profile_path = Path(profile_path) if profile_path else None
        self.tools_dir = Path(__file__).parent
        self.output_dir = self.tools_dir / "output"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
    def run_forensics_script(self):
        """Run the bash forensics script"""
        script_path = self.tools_dir / "firefox_forensics.sh"
        if not script_path.exists():
            logging.error(f"Forensics script not found: {script_path}")
            return False
            
        try:
            result = subprocess.run(
                [str(script_path)],
                capture_output=True,
                text=True,
                check=True
            )
            logging.info(result.stdout)
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Forensics script failed: {e}")
            logging.error(f"Output: {e.output}")
            return False
            
    def analyze_places_database(self):
        """Perform deep analysis of places.sqlite"""
        if not self.profile_path:
            logging.error("No profile path specified")
            return None
            
        places_db = self.profile_path / "places.sqlite"
        if not places_db.exists():
            logging.error(f"places.sqlite not found: {places_db}")
            return None
            
        # Create a temporary copy for analysis
        with tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False) as temp_db:
            temp_path = Path(temp_db.name)
            shutil.copy2(places_db, temp_path)
            
        try:
            results = {
                'deleted_entries': [],
                'statistics': {},
                'integrity': None
            }
            
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            
            # Get database statistics
            cursor.execute('PRAGMA page_size')
            results['statistics']['page_size'] = cursor.fetchone()[0]
            
            cursor.execute('PRAGMA freelist_count')
            results['statistics']['freelist_count'] = cursor.fetchone()[0]
            
            # Check database integrity
            cursor.execute('PRAGMA integrity_check')
            results['integrity'] = cursor.fetchone()[0]
            
            # Advanced recovery techniques
            # 1. Check WAL file
            cursor.execute('PRAGMA journal_mode=WAL')
            
            # 2. Look for partially overwritten records
            cursor.execute('''
                SELECT url, title, last_visit_date, visit_count
                FROM moz_places
                WHERE url NOT LIKE 'about:%'
                AND url NOT LIKE 'place:%'
                AND visit_count > 0
                ORDER BY last_visit_date DESC
            ''')
            
            for row in cursor.fetchall():
                url, title, date, count = row
                if any(x is not None and b'\x00' in str(x).encode() for x in (url, title)):
                    results['deleted_entries'].append({
                        'url': url,
                        'title': title,
                        'visit_date': date,
                        'visit_count': count,
                        'recovery_status': 'Partially overwritten'
                    })
            
            conn.close()
            return results
            
        except sqlite3.Error as e:
            logging.error(f"SQLite error: {e}")
            return None
        finally:
            temp_path.unlink(missing_ok=True)
            
    def parse_session_data(self):
        """Parse Firefox session data for deleted history"""
        if not self.profile_path:
            logging.error("No profile path specified")
            return []
            
        session_dir = self.profile_path / "sessionstore-backups"
        if not session_dir.exists():
            logging.error(f"Session directory not found: {session_dir}")
            return []
            
        deleted_history = []
        session_files = list(session_dir.glob("*.jsonlz4"))
        
        for session_file in session_files:
            try:
                # Use Python lz4 module instead of system command
                with open(session_file, 'rb') as f:
                    # Check for LZ4 header
                    header = f.read(8)
                    if header == b'mozLz40\0':
                        expected_size = struct.unpack('<I', f.read(4))[0]
                        compressed_data = f.read()
                        json_data = lz4.block.decompress(compressed_data, uncompressed_size=expected_size)
                        session_data = json.loads(json_data)
                    else:
                        # Try reading as regular JSON
                        f.seek(0)
                        session_data = json.loads(f.read().decode('utf-8'))
                
                # Extract URLs from windows and tabs
                for window in session_data.get('windows', []):
                    for tab in window.get('tabs', []):
                        entries = tab.get('entries', [])
                        for entry in entries:
                            url = entry.get('url', '')
                            title = entry.get('title', '')
                            last_accessed = entry.get('lastAccessed', 0)
                            
                            if url and not url.startswith(('about:', 'place:')):
                                deleted_history.append({
                                    'url': url,
                                    'title': title,
                                    'timestamp': last_accessed,
                                    'source': session_file.name
                                })
                                
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to decompress {session_file}: {e}")
            except json.JSONDecodeError as e:
                logging.error(f"Failed to parse {session_file}: {e}")
                
        return deleted_history
        
    def run_dumpzilla(self):
        """Run dumpzilla and parse its output"""
        if not self.profile_path:
            logging.error("No profile path specified")
            return None
            
        dumpzilla_path = self.tools_dir / "dumpzilla" / "dumpzilla.py"
        if not dumpzilla_path.exists():
            logging.error(f"Dumpzilla not found: {dumpzilla_path}")
            return None
            
        try:
            result = subprocess.run(
                ['python3', str(dumpzilla_path),
                 '--history', '--downloads', '--bookmarks',
                 '--cookies', '--preferences', '--cache',
                 '--all-json', str(self.profile_path)],
                capture_output=True,
                text=True,
                check=True
            )
            
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            logging.error(f"Dumpzilla failed: {e}")
            return None
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse dumpzilla output: {e}")
            return None
            
    def get_all_deleted_history(self):
        """Combine results from all recovery methods"""
        all_deleted = []
        
        # 1. Run the forensics script
        self.run_forensics_script()
        
        # 2. Analyze places database
        places_analysis = self.analyze_places_database()
        if places_analysis:
            all_deleted.extend(places_analysis.get('deleted_entries', []))
        
        # 3. Parse session data
        session_history = self.parse_session_data()
        all_deleted.extend(session_history)
        
        # 4. Run dumpzilla
        dumpzilla_data = self.run_dumpzilla()
        if dumpzilla_data:
            # Extract any additional history from dumpzilla
            if 'history' in dumpzilla_data:
                all_deleted.extend(dumpzilla_data['history'])
        
        return all_deleted

def main():
    """Main function for testing"""
    import argparse
    parser = argparse.ArgumentParser(description='Firefox Forensics Tool')
    parser.add_argument('--profile', help='Path to Firefox profile')
    args = parser.parse_args()
    
    forensics = FirefoxForensics(args.profile)
    deleted_history = forensics.get_all_deleted_history()
    
    output_file = forensics.output_dir / 'deleted_history.json'
    with open(output_file, 'w') as f:
        json.dump(deleted_history, f, indent=2)
    
    logging.info(f"Found {len(deleted_history)} potentially deleted history items")
    logging.info(f"Results saved to {output_file}")

if __name__ == '__main__':
    main()
