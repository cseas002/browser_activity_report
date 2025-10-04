#!/usr/bin/env python3
"""
Firefox Database Analyzer
Shows how database operations affect recoverable data
"""

import sqlite3
import logging
from pathlib import Path
import tempfile
import shutil

class DatabaseAnalyzer:
    def __init__(self, profile_path):
        self.profile_path = Path(profile_path)
        self.places_db = self.profile_path / "places.sqlite"
        
    def analyze_database_state(self):
        """Analyze current database state"""
        if not self.places_db.exists():
            print("Database not found!")
            return
            
        # Copy database to avoid locking
        with tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False) as temp_db:
            temp_path = Path(temp_db.name)
            shutil.copy2(self.places_db, temp_path)
            
        try:
            conn = sqlite3.connect(str(temp_path))
            cursor = conn.cursor()
            
            print("=== FIREFOX DATABASE ANALYSIS ===")
            print(f"Database: {self.places_db}")
            
            # Basic stats
            cursor.execute("PRAGMA page_size")
            page_size = cursor.fetchone()[0]
            print(f"Page size: {page_size:,} bytes")
            
            cursor.execute("PRAGMA page_count")
            page_count = cursor.fetchone()[0]
            print(f"Total pages: {page_count:,}")
            
            cursor.execute("PRAGMA freelist_count")
            free_pages = cursor.fetchone()[0]
            print(f"Free pages: {free_pages:,}")
            
            free_space = free_pages * page_size
            print(f"Free space: {free_space:,} bytes ({free_space/1024/1024:.2f} MB)")
            
            # Database integrity
            cursor.execute("PRAGMA integrity_check")
            integrity = cursor.fetchone()[0]
            print(f"Database integrity: {integrity}")
            
            # Table stats
            cursor.execute("SELECT count(*) FROM moz_places")
            places_count = cursor.fetchone()[0]
            print(f"Places records: {places_count:,}")
            
            cursor.execute("SELECT count(*) FROM moz_historyvisits")
            visits_count = cursor.fetchone()[0]
            print(f"History visits: {visits_count:,}")
            
            # WAL file info
            wal_path = self.places_db.parent / (self.places_db.name + "-wal")
            if wal_path.exists():
                wal_size = wal_path.stat().st_size
                print(f"WAL file size: {wal_size:,} bytes ({wal_size/1024/1024:.2f} MB)")
            else:
                print("WAL file: Not present")
                
            # Journal file info
            journal_path = self.places_db.parent / (self.places_db.name + "-journal")
            if journal_path.exists():
                journal_size = journal_path.stat().st_size
                print(f"Journal file size: {journal_size:,} bytes")
            else:
                print("Journal file: Not present")
                
            print("\n=== RECOVERY POTENTIAL ===")
            if free_pages > 0:
                print(f"✅ {free_pages:,} free pages available for recovery")
                print("   These may contain deleted history records")
            else:
                print("❌ No free pages - database has been vacuumed")
                print("   Deleted data is likely permanently lost")
                
            if wal_path.exists() and wal_size > 0:
                print(f"✅ WAL file contains {wal_size:,} bytes of recent changes")
                print("   May contain recently deleted history")
            else:
                print("❌ No WAL file - no recent changes to recover")
                
            print("\n=== WHY DELETING MORE SHOWS LESS ===")
            print("1. Normal deletion: Records marked as deleted, space marked as 'free'")
            print("2. Heavy deletion: May trigger database VACUUM operation")
            print("3. VACUUM: Reorganizes database, overwrites free space")
            print("4. Result: Previously recoverable data is permanently destroyed")
            print("\n💡 TIP: For maximum recovery, analyze immediately after deletion!")
            
            conn.close()
            
        except Exception as e:
            print(f"Error analyzing database: {e}")
        finally:
            temp_path.unlink(missing_ok=True)
            
    def simulate_vacuum_effect(self):
        """Demonstrate what happens during vacuum"""
        print("\n=== VACUUM SIMULATION ===")
        print("Before VACUUM:")
        print("  - Free pages: Contains deleted data (recoverable)")
        print("  - WAL file: Contains recent changes")
        print("  - Recovery potential: HIGH")
        print("\nAfter VACUUM:")
        print("  - Free pages: 0 (data overwritten)")
        print("  - WAL file: May be cleared")
        print("  - Recovery potential: LOW")
        print("\nThis is why deleting MORE history shows LESS deleted history!")

def main():
    import sys
    if len(sys.argv) != 2:
        print("Usage: database_analyzer.py path/to/firefox/profile")
        sys.exit(1)
        
    profile_path = Path(sys.argv[1])
    if not profile_path.exists():
        print(f"Profile directory not found: {profile_path}")
        sys.exit(1)
        
    analyzer = DatabaseAnalyzer(profile_path)
    analyzer.analyze_database_state()
    analyzer.simulate_vacuum_effect()

if __name__ == "__main__":
    main()
