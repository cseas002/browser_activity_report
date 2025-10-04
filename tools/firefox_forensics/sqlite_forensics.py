#!/usr/bin/env python3
"""
SQLite Forensics Tool for Firefox History Recovery
"""

import sqlite3
import logging
import sys
from pathlib import Path
import struct
import json
import csv
from datetime import datetime

import re

class SQLiteForensics:
    def __init__(self, db_path):
        self.db_path = Path(db_path)
        self.output_dir = Path("data/raw")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logging.basicConfig(level=logging.INFO)
        
    def analyze_free_pages(self):
        """Analyze free pages in SQLite database for deleted records"""
        deleted_records = []
        
        # Copy database to avoid modifying original
        temp_db = self.output_dir / "temp_analysis.sqlite"
        temp_db.write_bytes(self.db_path.read_bytes())
        
        try:
            # Open database with special flags
            conn = sqlite3.connect(str(temp_db))
            conn.row_factory = sqlite3.Row
            
            # Get database page size
            page_size = conn.execute("PRAGMA page_size").fetchone()[0]
            
            # Get free pages
            free_pages = conn.execute("PRAGMA freelist_count").fetchone()[0]
            
            if free_pages > 0:
                logging.info(f"Found {free_pages} free pages")
                
                # Read database file as binary
                with open(temp_db, 'rb') as f:
                    db_data = f.read()
                
                # Scan for URL patterns in free pages
                import re
                url_pattern = rb'https?://[^\s\x00-\x1F\x7F-\xFF]{3,}'
                title_pattern = rb'[A-Za-z0-9\s\-_]{3,}'
                
                urls = re.finditer(url_pattern, db_data)
                for match in urls:
                    url = match.group(0).decode('utf-8', errors='ignore')
                    
                    # Look for title near URL
                    surrounding = db_data[max(0, match.start()-100):match.end()+100]
                    titles = re.finditer(title_pattern, surrounding)
                    title = ""
                    for t in titles:
                        candidate = t.group(0).decode('utf-8', errors='ignore')
                        if len(candidate) > len(title) and candidate not in url:
                            title = candidate
                    
                    if url and title:
                        record = {
                            'url': url,
                            'title': f'[RECOVERED FROM FREE SPACE] {title}',
                            'recovery_method': 'sqlite_free_pages'
                        }
                        deleted_records.append(record)
            
            # Check for orphaned records
            cursor = conn.cursor()
            cursor.execute("""
                SELECT url, title 
                FROM moz_places 
                WHERE id NOT IN (SELECT place_id FROM moz_historyvisits)
                AND url NOT LIKE 'place:%'
                AND url NOT LIKE 'about:%'
            """)
            
            for row in cursor:
                if row['url'] and row['title']:
                    record = {
                        'url': row['url'],
                        'title': f'[ORPHANED RECORD] {row["title"]}',
                        'recovery_method': 'orphaned_record'
                    }
                    deleted_records.append(record)
            
            # Check WAL file if it exists
            wal_path = self.db_path.parent / (self.db_path.name + "-wal")
            if wal_path.exists():
                with open(wal_path, 'rb') as f:
                    wal_data = f.read()
                    urls = re.finditer(url_pattern, wal_data)
                    for match in urls:
                        url = match.group(0).decode('utf-8', errors='ignore')
                        if url:
                            record = {
                                'url': url,
                                'title': '[RECOVERED FROM WAL]',
                                'recovery_method': 'wal_recovery'
                            }
                            deleted_records.append(record)
            
            # Check journal file if it exists
            journal_path = self.db_path.parent / (self.db_path.name + "-journal")
            if journal_path.exists():
                with open(journal_path, 'rb') as f:
                    journal_data = f.read()
                    urls = re.finditer(url_pattern, journal_data)
                    for match in urls:
                        url = match.group(0).decode('utf-8', errors='ignore')
                        if url:
                            record = {
                                'url': url,
                                'title': '[RECOVERED FROM JOURNAL]',
                                'recovery_method': 'journal_recovery'
                            }
                            deleted_records.append(record)
            
        except Exception as e:
            logging.error(f"Error analyzing database: {e}")
        finally:
            if 'conn' in locals():
                conn.close()
            if temp_db.exists():
                temp_db.unlink()
        
        return deleted_records

    def save_recovered_records(self, records):
        """Save recovered records to CSV"""
        output_file = self.output_dir / "sqlite_forensics_results.csv"
        
        fieldnames = ['url', 'title', 'recovery_method', 'timestamp']
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for record in records:
                writer.writerow(record)
        
        logging.info(f"Saved {len(records)} recovered records to {output_file}")

def main():
    if len(sys.argv) != 2:
        print("Usage: sqlite_forensics.py path/to/places.sqlite")
        sys.exit(1)
    
    db_path = Path(sys.argv[1])
    if not db_path.exists():
        print(f"Database not found: {db_path}")
        sys.exit(1)
    
    forensics = SQLiteForensics(db_path)
    records = forensics.analyze_free_pages()
    forensics.save_recovered_records(records)

if __name__ == "__main__":
    main()
