#!/usr/bin/env python3
import sqlite3
import sys
from pathlib import Path

def scan_for_deleted(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Look for orphaned history entries
    cursor.execute("""
        SELECT url, title, last_visit_date 
        FROM moz_places 
        WHERE id NOT IN (SELECT place_id FROM moz_historyvisits)
        AND url NOT LIKE 'place:%'
        AND url NOT LIKE 'about:%'
        AND title IS NOT NULL
    """)
    
    print("\nOrphaned History Entries:")
    for row in cursor.fetchall():
        print(f"URL: {row[0]}")
        print(f"Title: {row[1]}")
        print("-" * 50)
    
    # Check database stats
    cursor.execute("PRAGMA page_size")
    page_size = cursor.fetchone()[0]
    
    cursor.execute("PRAGMA freelist_count")
    free_pages = cursor.fetchone()[0]
    
    print(f"\nDatabase Stats:")
    print(f"Page Size: {page_size}")
    print(f"Free Pages: {free_pages}")
    print(f"Total Free Space: {free_pages * page_size:,} bytes")
    
    conn.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: quick_scan.py path/to/places.sqlite")
        sys.exit(1)
    
    scan_for_deleted(sys.argv[1])
