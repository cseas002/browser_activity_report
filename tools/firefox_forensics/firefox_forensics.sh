#!/bin/bash

# Firefox Forensics Wrapper Script
# This script integrates multiple Firefox forensic tools

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$SCRIPT_DIR/output"
TEMP_DIR="$SCRIPT_DIR/temp"

# Create necessary directories
mkdir -p "$OUTPUT_DIR" "$TEMP_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check and install dependencies
check_dependencies() {
    local missing_deps=()
    
    # Check for required commands
    for cmd in cargo mozlz4 sqlite3 python3; do
        if ! command_exists "$cmd"; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${RED}Missing dependencies: ${missing_deps[*]}${NC}"
        echo "Please install them using:"
        echo "sudo apt install -y cargo mozlz4-tools sqlite3 python3"
        exit 1
    fi
}

# Function to find Firefox profiles
find_firefox_profiles() {
    local mozilla_dir="$HOME/.mozilla/firefox"
    if [ ! -d "$mozilla_dir" ]; then
        echo -e "${RED}Firefox directory not found: $mozilla_dir${NC}"
        return 1
    fi
    
    echo -e "${GREEN}Found Firefox profiles:${NC}"
    find "$mozilla_dir" -name "places.sqlite" -exec dirname {} \;
}

# Function to extract session data
extract_session_data() {
    local profile_dir="$1"
    local session_dir="$profile_dir/sessionstore-backups"
    
    if [ ! -d "$session_dir" ]; then
        echo -e "${YELLOW}No session backup directory found${NC}"
        return 0
    fi
    
    echo -e "${GREEN}Extracting session data...${NC}"
    
    for session_file in "$session_dir"/*.jsonlz4; do
        if [ -f "$session_file" ]; then
            local output_file="$OUTPUT_DIR/$(basename "${session_file%.*}").json"
            echo "Processing $session_file"
            mozlz4 -d "$session_file" > "$output_file" 2>/dev/null || \
                echo -e "${RED}Failed to extract $session_file${NC}"
        fi
    done
}

# Function to analyze places database
analyze_places_db() {
    local profile_dir="$1"
    local places_db="$profile_dir/places.sqlite"
    
    if [ ! -f "$places_db" ]; then
        echo -e "${RED}places.sqlite not found in $profile_dir${NC}"
        return 1
    fi
    
    echo -e "${GREEN}Analyzing places database...${NC}"
    
    # Create a copy for analysis
    cp "$places_db" "$TEMP_DIR/places_analysis.sqlite"
    
    # Get database statistics
    echo "Database Statistics:"
    sqlite3 "$TEMP_DIR/places_analysis.sqlite" <<EOF
.headers on
PRAGMA page_size;
PRAGMA freelist_count;
SELECT count(*) as total_urls FROM moz_places;
SELECT count(*) as total_visits FROM moz_historyvisits;
EOF
    
    # Extract deleted entries from free pages
    echo -e "${GREEN}Searching for deleted entries...${NC}"
    sqlite3 "$TEMP_DIR/places_analysis.sqlite" "PRAGMA integrity_check;"
    
    # Dump database for further analysis
    sqlite3 "$TEMP_DIR/places_analysis.sqlite" ".dump" > "$OUTPUT_DIR/places_dump.sql"
}

# Function to run dumpzilla
run_dumpzilla() {
    local profile_dir="$1"
    
    if [ -d "$SCRIPT_DIR/dumpzilla" ]; then
        echo -e "${GREEN}Running dumpzilla...${NC}"
        python3 "$SCRIPT_DIR/dumpzilla/dumpzilla.py" \
            --history --downloads --bookmarks --cookies \
            --preferences --cache --all-json \
            "$profile_dir" > "$OUTPUT_DIR/dumpzilla_output.json" 2>/dev/null || \
            echo -e "${RED}Dumpzilla failed${NC}"
    else
        echo -e "${RED}Dumpzilla not found in $SCRIPT_DIR/dumpzilla${NC}"
    fi
}

# Main execution
main() {
    echo -e "${GREEN}Firefox Forensics Tool${NC}"
    echo "================================"
    
    # Check dependencies
    check_dependencies
    
    # Find Firefox profiles
    local profiles
    mapfile -t profiles < <(find_firefox_profiles)
    
    if [ ${#profiles[@]} -eq 0 ]; then
        echo -e "${RED}No Firefox profiles found${NC}"
        exit 1
    fi
    
    # Process each profile
    for profile in "${profiles[@]}"; do
        echo -e "\n${GREEN}Processing profile: $profile${NC}"
        echo "================================"
        
        # Extract session data
        extract_session_data "$profile"
        
        # Analyze places database
        analyze_places_db "$profile"
        
        # Run dumpzilla
        run_dumpzilla "$profile"
    done
    
    echo -e "\n${GREEN}Processing complete!${NC}"
    echo "Results saved in: $OUTPUT_DIR"
}

# Run main function
main "$@"
