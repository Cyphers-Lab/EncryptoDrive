#!/bin/bash

# Build script for EncryptoDrive on Linux/macOS

# Exit on error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}EncryptoDrive Build Script${NC}"

# Check for required tools
check_dependency() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}Error: $1 is required but not installed.${NC}"
        exit 1
    fi
}

check_dependency cmake
check_dependency make
check_dependency pkg-config

# Create build directory
echo -e "${YELLOW}Creating build directory...${NC}"
mkdir -p build
cd build

# Create and set permissions for test directories
echo -e "${YELLOW}Creating test directories...${NC}"
mkdir -p test-output test-data
chmod -R 777 test-output test-data

# Configure with CMake
echo -e "${YELLOW}Configuring with CMake...${NC}"
cmake .. -DCMAKE_BUILD_TYPE=Debug  # Use Debug for better error reporting

# Build
echo -e "${YELLOW}Building...${NC}"
cmake --build . --config Debug -j$(nproc)

# Run tests with more verbose output
echo -e "${YELLOW}Running tests...${NC}"
GTEST_COLOR=1 ctest -V --output-on-failure

echo -e "${GREEN}Build completed successfully!${NC}"
echo "You can find the binaries in build/bin/" 