@echo off
setlocal enabledelayedexpansion

echo EncryptoDrive Build Script

REM Check for required tools
where cmake >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Error: cmake is required but not installed.
    exit /b 1
)

REM Create build directory
echo Creating build directory...
if not exist build mkdir build
cd build

REM Configure with CMake
echo Configuring with CMake...
if defined VCPKG_ROOT (
    cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake"
) else (
    cmake .. -DCMAKE_BUILD_TYPE=Release
)
if %ERRORLEVEL% neq 0 goto error

REM Build
echo Building...
cmake --build . --config Release
if %ERRORLEVEL% neq 0 goto error

REM Run tests
echo Running tests...
ctest --output-on-failure -C Release
if %ERRORLEVEL% neq 0 goto error

echo Build completed successfully!
echo You can find the binaries in build\bin\
exit /b 0

:error
echo Build failed!
exit /b 1 