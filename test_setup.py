#!/usr/bin/env python3
"""
Quick test script to verify the forensics environment is working
"""

import sys
import os
import sqlite3
import csv
import json
from datetime import datetime

def test_basic_functionality():
    """Test basic Python functionality for forensics work."""
    print("Testing basic functionality...")

    # Test SQLite
    try:
        conn = sqlite3.connect(':memory:')
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE test (id INTEGER, data TEXT)')
        cursor.execute('INSERT INTO test VALUES (1, "test data")')
        cursor.execute('SELECT * FROM test')
        result = cursor.fetchone()
        assert result == (1, "test data")
        conn.close()
        print("✓ SQLite functionality working")
    except Exception as e:
        print(f"✗ SQLite test failed: {e}")
        return False

    # Test CSV handling
    try:
        with open('test_temp.csv', 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['col1', 'col2'])
            writer.writerow(['data1', 'data2'])

        with open('test_temp.csv', 'r') as csvfile:
            reader = csv.reader(csvfile)
            rows = list(reader)
            assert rows == [['col1', 'col2'], ['data1', 'data2']]

        os.remove('test_temp.csv')
        print("✓ CSV handling working")
    except Exception as e:
        print(f"✗ CSV test failed: {e}")
        return False

    # Test JSON handling
    try:
        test_data = {'timestamp': datetime.now().isoformat(), 'test': 'data'}
        with open('test_temp.json', 'w') as f:
            json.dump(test_data, f)

        with open('test_temp.json', 'r') as f:
            loaded_data = json.load(f)
            assert loaded_data['test'] == 'data'

        os.remove('test_temp.json')
        print("✓ JSON handling working")
    except Exception as e:
        print(f"✗ JSON test failed: {e}")
        return False

    return True

def test_script_imports():
    """Test that our scripts can be imported."""
    print("Testing script imports...")

    scripts_dir = 'scripts'

    # Test browser_extractor
    try:
        sys.path.insert(0, scripts_dir)
        from browser_extractor import BrowserExtractor
        print("✓ Browser extractor import working")
    except ImportError as e:
        print(f"✗ Browser extractor import failed: {e}")
        return False

    # Test analyze_artifacts
    try:
        from analyze_artifacts import BrowserAnalyzer
        print("✓ Artifact analyzer import working")
    except ImportError as e:
        print(f"✗ Artifact analyzer import failed: {e}")
        return False

    # Test generate_report
    try:
        from generate_report import ForensicReportGenerator
        print("✓ Report generator import working")
    except ImportError as e:
        print(f"✗ Report generator import failed: {e}")
        return False

    return True

if __name__ == "__main__":
    print("Browser Forensics Environment Test")
    print("=" * 40)

    success = True

    # Test basic functionality
    if not test_basic_functionality():
        success = False

    print()

    # Test script imports
    if not test_script_imports():
        success = False

    print()

    if success:
        print("✓ All tests passed! Environment is ready for browser forensics.")
        print("\nNext steps:")
        print("1. Run the demo: python scripts/demo_workflow.py")
        print("2. Extract real data: python scripts/browser_extractor.py")
        print("3. Analyze data: python scripts/analyze_artifacts.py")
        print("4. Generate report: python scripts/generate_report.py")
    else:
        print("✗ Some tests failed. Please check the error messages above.")
        print("\nTroubleshooting:")
        print("1. Ensure Python 3.6+ is installed")
        print("2. Run: pip install pandas matplotlib seaborn browserhistory requests beautifulsoup4 lxml")
        print("3. Check that scripts are in the scripts/ directory")

    sys.exit(0 if success else 1)

