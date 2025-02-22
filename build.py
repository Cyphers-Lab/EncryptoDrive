#!/usr/bin/env python3

import os
import sys
import platform
import subprocess
import argparse
from pathlib import Path

def print_colored(text, color):
    colors = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'reset': '\033[0m'
    }
    if sys.platform == 'win32':
        print(text)
    else:
        print(f"{colors.get(color, '')}{text}{colors['reset']}")

def run_command(cmd, error_msg="Command failed"):
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print_colored(f"Error: {error_msg}", 'red')
        print(f"Command failed with exit code {e.returncode}")
        sys.exit(1)

def setup_test_env(build_dir):
    test_dirs = ['test-output', 'test-data']
    for dir_name in test_dirs:
        dir_path = build_dir / dir_name
        dir_path.mkdir(exist_ok=True)
        # Make directory writable
        dir_path.chmod(0o777)

def main():
    parser = argparse.ArgumentParser(description='Build EncryptoDrive')
    parser.add_argument('--debug', action='store_true', help='Build in debug mode')
    parser.add_argument('--no-tests', action='store_true', help='Skip running tests')
    parser.add_argument('--clean', action='store_true', help='Clean build directory')
    args = parser.parse_args()

    print_colored("EncryptoDrive Build Script", 'green')

    # Determine platform
    system = platform.system()
    is_windows = system == 'Windows'

    # Create build directory
    build_dir = Path('build')
    if args.clean and build_dir.exists():
        print_colored("Cleaning build directory...", 'yellow')
        if is_windows:
            run_command(['rmdir', '/s', '/q', str(build_dir)])
        else:
            run_command(['rm', '-rf', str(build_dir)])

    build_dir.mkdir(exist_ok=True)
    os.chdir(str(build_dir))

    # Configure CMake
    print_colored("Configuring with CMake...", 'yellow')
    cmake_args = [
        'cmake',
        '..',
        f'-DCMAKE_BUILD_TYPE={"Debug" if args.debug else "Release"}'
    ]

    if is_windows and 'VCPKG_ROOT' in os.environ:
        vcpkg_path = Path(os.environ['VCPKG_ROOT'])
        cmake_args.append(f'-DCMAKE_TOOLCHAIN_FILE={vcpkg_path}/scripts/buildsystems/vcpkg.cmake')

    run_command(cmake_args, "CMake configuration failed")

    # Build
    print_colored("Building...", 'yellow')
    build_args = ['cmake', '--build', '.', '--config', 'Debug' if args.debug else 'Release']
    if not is_windows:
        build_args.extend(['-j', str(os.cpu_count() or 1)])
    run_command(build_args, "Build failed")

    # Run tests
    if not args.no_tests:
        print_colored("Running tests...", 'yellow')
        run_command(['ctest', '--output-on-failure', '-C', 'Debug' if args.debug else 'Release'],
                   "Tests failed")

    # Setup test environment
    setup_test_env(build_dir)

    print_colored("Build completed successfully!", 'green')
    print(f"You can find the binaries in {build_dir}/bin/")

if __name__ == '__main__':
    main() 