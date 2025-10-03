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

# Check if we're in an Anaconda/miniconda environment
if [[ -n "$CONDA_DEFAULT_ENV" ]]; then
    echo "Detected Anaconda environment: $CONDA_DEFAULT_ENV"
    echo "Using conda for package installation..."
    CONDA_PYTHON=true
else
    echo "Not in Anaconda environment. Setting up virtual environment..."
    
    # Create virtual environment
    VENV_DIR="browser_forensics_env"
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
    CONDA_PYTHON=false
fi

echo "Using Python: $($PYTHON_CMD --version)"
echo "Using Pip: $($PIP_CMD --version)"

# Install required Python packages
echo "Installing required Python packages..."

if [[ "$CONDA_PYTHON" == "true" ]]; then
    # Use conda for core packages, pip for packages not available in conda
    echo "Installing core packages with conda..."
    conda install -c conda-forge -y pandas matplotlib seaborn requests
    
    echo "Installing additional packages with pip..."
    # Use pip within conda environment for packages not available via conda
    pip install browserhistory beautifulsoup4 lxml
else
    # Use pip in virtual environment
    $PIP_CMD install pandas matplotlib seaborn
    $PIP_CMD install browserhistory
    $PIP_CMD install requests beautifulsoup4 lxml
fi

echo "Python dependencies installed successfully."

# Install system tools based on OS
if [[ "$OS" == "linux" ]]; then
    echo "Installing Linux-specific tools..."
    
    # Update package list
    sudo apt-get update
    
    # Install SQLite browser for manual database inspection
    sudo apt-get install -y sqlitebrowser
    
    # Install forensics tools
    sudo apt-get install -y exiftool
    
    # Install development tools
    sudo apt-get install -y git curl wget
    
    echo "Linux tools installed."
    
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
mkdir -p data/raw
mkdir -p data/processed
mkdir -p reports
mkdir -p tools
mkdir -p documentation

# Make scripts executable
chmod +x scripts/*.py
chmod +x scripts/*.sh

# Copy the test script (created separately to avoid heredoc issues)
echo "Setting up test script..."
cp scripts/test_setup_template.py test_setup.py
chmod +x test_setup.py

echo ""
echo "========================================="
echo "Setup Complete!"
echo "========================================="

# Provide activation instructions and test the installation
if [[ "$CONDA_PYTHON" == "true" ]]; then
    echo ""
    echo "✓ Anaconda environment detected and configured!"
    echo ""
    echo "All packages are installed in your current Anaconda environment."
    echo "Make sure to activate this environment before running scripts:"
    echo "conda activate $CONDA_DEFAULT_ENV"
    echo ""
    echo "To test your installation, run:"
    echo "python test_setup.py"
    echo ""
    echo "Testing installation in Anaconda environment..."
    # Test the installation (simple check)
    if python -c "import pandas, matplotlib, browserhistory" 2>/dev/null; then
        echo "✓ Python packages installed successfully"
    else
        echo "⚠ Package verification failed, but installation completed"
    fi
else
    echo ""
    echo "✓ Virtual environment created and configured!"
    echo ""
    echo "To use the browser forensics tools, always activate the virtual environment first:"
    echo "source browser_forensics_env/bin/activate"
    echo ""
    echo "To test your installation, run:"
    echo "source browser_forensics_env/bin/activate"
    echo "python test_setup.py"
    echo ""
    echo "To run the forensics tools:"
    echo "source browser_forensics_env/bin/activate"
    echo "python scripts/browser_extractor.py"
    echo "python scripts/analyze_artifacts.py"
    echo "python scripts/generate_report.py"
    echo ""
    echo "Testing installation in virtual environment..."
    # Test the installation
    source browser_forensics_env/bin/activate
    if python -c "import pandas, matplotlib, browserhistory" 2>/dev/null; then
        echo "✓ Python packages installed successfully"
    else
        echo "⚠ Package verification failed, but installation completed"
    fi
fi

echo ""
echo "For help with individual scripts, use: python script_name.py --help"
echo ""
echo "Documentation is available in the documentation/ directory"
echo ""
echo "Happy forensics! 🔍"
