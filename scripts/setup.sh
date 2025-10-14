#!/bin/bash

# Browser Forensics Environment Setup Script
# This script sets up the necessary tools and dependencies for browser artifact analysis

set -e  # Exit on any error

echo "========================================="
echo "Browser Forensics Environment Setup"
echo "========================================="

# Detect operating system
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    OS="windows"
else
    echo "Unsupported operating system: $OSTYPE"
    exit 1
fi

echo "Detected OS: $OS"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Check for Python and determine best approach
echo "Checking Python installation..."
if command_exists python3; then
    PYTHON_CMD="python3"
    PIP_CMD="pip3"
    elif command_exists python; then
    PYTHON_CMD="python"
    PIP_CMD="pip"
else
    echo "Python not found. Installing Python..."
    if [[ "$OS" == "linux" ]]; then
        sudo apt-get update
        sudo apt-get install -y python3 python3-pip python3-venv
        elif [[ "$OS" == "macos" ]]; then
        # Check if Homebrew is installed
        if ! command_exists brew; then
            echo "Homebrew not found. Please install Homebrew first: https://brew.sh/"
            exit 1
        fi
        brew install python3
    else
        echo "Please install Python 3.6+ manually from https://python.org"
        exit 1
    fi
fi

echo "Using Python: $($PYTHON_CMD --version)"

# Force virtual environment setup (no conda)
echo "Setting up virtual environment..."

# Use existing .venv directory or create it in project root
VENV_DIR="$PROJECT_ROOT/.venv"
if [[ ! -d "$VENV_DIR" ]]; then
    echo "Creating virtual environment: $VENV_DIR"
    $PYTHON_CMD -m venv "$VENV_DIR"
    if [[ $? -ne 0 ]]; then
        echo "Failed to create virtual environment. Installing python3-venv..."
        if [[ "$OS" == "linux" ]]; then
            sudo apt-get install -y python3-venv
        fi
        $PYTHON_CMD -m venv "$VENV_DIR"
    fi
else
    echo "Virtual environment already exists: $VENV_DIR"
fi

# Activate virtual environment for package installation
echo "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

# Update pip in virtual environment
pip install --upgrade pip

PYTHON_CMD="$VENV_DIR/bin/python"
PIP_CMD="$VENV_DIR/bin/pip"

echo "Using Python: $("$PYTHON_CMD" --version)"
echo "Using Pip: $("$PIP_CMD" --version)"

# Install required Python packages
echo "Installing required Python packages..."

# Check if requirements.txt exists
if [[ -f "$PROJECT_ROOT/requirements.txt" ]]; then
    echo "Installing packages from requirements.txt..."
    "$PIP_CMD" install -r "$PROJECT_ROOT/requirements.txt"
else
    echo "requirements.txt not found, installing packages individually..."
    # Fallback to individual package installation
    "$PIP_CMD" install pandas matplotlib seaborn plotly
    "$PIP_CMD" install browserhistory
    "$PIP_CMD" install requests beautifulsoup4 lxml
    "$PIP_CMD" install lz4  # For Firefox session file decompression
    "$PIP_CMD" install reportlab  # For PDF generation
    "$PIP_CMD" install markdown
fi

echo "Python dependencies installed successfully."

# Install system tools based on OS
if [[ "$OS" == "linux" ]]; then
    echo "Installing Linux-specific tools..."
    bash install_firefox_tools.sh
    elif [[ "$OS" == "macos" ]]; then
    echo "Installing macOS-specific tools..."
    
    # Check for Homebrew
    if ! command_exists brew; then
        echo "Homebrew not found. Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    # Install tools via Homebrew
    brew install exiftool
    brew install wget
    brew install git
    
    # Try to install sqlitebrowser (may not be available)
    if brew install --cask sqlitebrowser 2>/dev/null; then
        echo "✓ SQLite browser installed"
    else
        echo "⚠ SQLite browser not available via Homebrew, you can install it manually from https://sqlitebrowser.org/"
    fi
    
    echo "macOS tools installed."
    
    elif [[ "$OS" == "windows" ]]; then
    echo "Windows setup instructions:"
    echo "1. Install Python 3.6+ from https://python.org"
    echo "2. Install DB Browser for SQLite from https://sqlitebrowser.org/"
    echo "3. Install ExifTool from https://exiftool.org/"
    echo "4. Install Git from https://git-scm.com/"
    echo ""
    echo "Run the following commands in PowerShell as Administrator:"
    echo "python -m pip install pandas matplotlib seaborn browserhistory requests beautifulsoup4 lxml"
fi

# Create necessary directories
echo "Creating project directories..."
mkdir -p "$PROJECT_ROOT/data/raw"
mkdir -p "$PROJECT_ROOT/data/processed"
mkdir -p "$PROJECT_ROOT/reports"
mkdir -p "$PROJECT_ROOT/tools"
mkdir -p "$PROJECT_ROOT/documentation"

# Make scripts executable
chmod +x "$SCRIPT_DIR"/*.py
chmod +x "$SCRIPT_DIR"/*.sh

# Copy the test script (created separately to avoid heredoc issues)
echo "Setting up test script..."
cp "$SCRIPT_DIR/test_setup_template.py" "$PROJECT_ROOT/test_setup.py"
chmod +x "$PROJECT_ROOT/test_setup.py"

echo ""
echo "========================================="
echo "Setup Complete!"
echo "========================================="

# Provide activation instructions and test the installation
echo ""
echo "✓ Virtual environment created and configured!"
echo ""
echo "To use the browser forensics tools, always activate the virtual environment first:"
echo "source .venv/bin/activate"
echo ""
echo "To test your installation, run:"
echo "source .venv/bin/activate"
echo "python test_setup.py"
echo ""
echo "To run the forensics tools:"
echo "source .venv/bin/activate"
echo "python scripts/browser_extractor.py"
echo "python scripts/analyze_artifacts.py"
echo "python scripts/generate_report.py"
echo ""
echo "Testing installation in virtual environment..."
# Test the installation
source "$VENV_DIR/bin/activate"
if "$PYTHON_CMD" -c "import pandas, matplotlib, browserhistory, lz4" 2>/dev/null; then
    echo "✓ Python packages installed successfully"
else
    echo "⚠ Package verification failed, but installation completed"
fi

echo ""
echo "For help with individual scripts, use: python script_name.py --help"
echo ""
echo "To add new Python dependencies, edit requirements.txt and run:"
echo "source .venv/bin/activate"
echo "pip install -r requirements.txt"
echo ""
echo "Documentation is available in the documentation/ directory"

echo "NOW RUN source .venv/bin/activate !"