#!/bin/bash

# Firefox Forensics Tools Installation Script
# Installs the missing tools that cause the mozlz4 error

echo "========================================="
echo "Installing Firefox Forensics Tools"
echo "========================================="

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "This script should not be run as root for security reasons"
   exit 1
fi

# Update package list
echo "Updating package list..."
sudo apt update

# Install basic tools
echo "Installing basic tools..."
sudo apt install -y sqlite3 mozlz4-tools

# Install Rust if not present
if ! command -v cargo &> /dev/null; then
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
    echo "Rust installed. Please run 'source ~/.cargo/env' or restart your terminal"
fi

# Install firefed
if ! command -v firefed &> /dev/null; then
    echo "Installing firefed..."
    cargo install firefed
else
    echo "firefed already installed"
fi

# Install dumpzilla
if ! command -v dumpzilla &> /dev/null; then
    echo "Installing dumpzilla..."
    sudo apt install -y dumpzilla
else
    echo "dumpzilla already installed"
fi

# Install Python lz4 module
echo "Installing Python lz4 module..."
pip3 install lz4

echo ""
echo "========================================="
echo "Installation Complete!"
echo "========================================="
echo ""
echo "Installed tools:"
echo "✓ sqlite3 - SQLite command line tool"
echo "✓ mozlz4-tools - Mozilla LZ4 compression tools"
echo "✓ firefed - Firefox forensics tool (via cargo)"
echo "✓ dumpzilla - Firefox data extraction tool"
echo "✓ lz4 - Python LZ4 module"
echo ""
echo "You can now run the browser extractor without errors:"
echo "python3 scripts/browser_extractor.py"
echo ""
