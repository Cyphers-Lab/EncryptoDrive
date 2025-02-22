# Build script for EncryptoDrive on Windows

# Stop on error
$ErrorActionPreference = "Stop"

Write-Host "EncryptoDrive Build Script" -ForegroundColor Green

# Check for required tools
function Test-Dependency {
    param (
        [string]$Command
    )
    
    if (!(Get-Command $Command -ErrorAction SilentlyContinue)) {
        Write-Host "Error: $Command is required but not installed." -ForegroundColor Red
        exit 1
    }
}

Test-Dependency cmake
Test-Dependency msbuild

# Check for vcpkg
$vcpkgPath = $env:VCPKG_ROOT
if (-not $vcpkgPath) {
    Write-Host "Warning: VCPKG_ROOT environment variable not set." -ForegroundColor Yellow
    Write-Host "You may need to specify vcpkg toolchain manually." -ForegroundColor Yellow
}

# Create build directory
Write-Host "Creating build directory..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path build | Out-Null
Set-Location build

# Configure with CMake
Write-Host "Configuring with CMake..." -ForegroundColor Yellow
if ($vcpkgPath) {
    cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE="$vcpkgPath/scripts/buildsystems/vcpkg.cmake"
} else {
    cmake .. -DCMAKE_BUILD_TYPE=Release
}

# Build
Write-Host "Building..." -ForegroundColor Yellow
cmake --build . --config Release

# Run tests
Write-Host "Running tests..." -ForegroundColor Yellow
ctest --output-on-failure -C Release

Write-Host "Build completed successfully!" -ForegroundColor Green
Write-Host "You can find the binaries in build\bin\" 