# EncryptoDrive Core Library

Core components for secure file storage and synchronization system. Implements file integrity verification, version control, and cryptographic signatures.

## Components

### 1. File Integrity (MerkleTree)
- Provides incremental integrity verification using Merkle trees
- Supports efficient updates and verification of individual paths
- Generates and verifies inclusion proofs

### 2. Version Control
- **FileVersion**: Manages individual file versions with delta compression
- **VersionStore**: Provides file version tracking and management
- Implements configurable version pruning policies

### 3. Cryptographic Signatures
- Implements EdDSA (Ed25519) signatures for digital authentication
- Certificate chain management and validation
- PEM format support for keys and certificates

## Building

### Prerequisites

#### Required Dependencies
- C++17 compliant compiler (GCC 7+, Clang 6+, or MSVC 2019+)
- CMake 3.15 or higher
- OpenSSL development libraries
- SQLite3 development libraries
- nlohmann_json library
- Qt6 (for GUI components)
- Google Test framework (for testing)

#### Installing Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install build-essential cmake libssl-dev libsqlite3-dev \
    qt6-base-dev nlohmann-json3-dev libgtest-dev zlib1g-dev
```

**Fedora:**
```bash
sudo dnf install gcc-c++ cmake openssl-devel sqlite-devel qt6-qtbase-devel \
    json-devel gtest-devel zlib-devel
```

**macOS (using Homebrew):**
```bash
brew install cmake openssl sqlite qt6 nlohmann-json googletest zlib
```

**Windows (using vcpkg):**
```powershell
vcpkg install openssl:x64-windows sqlite3:x64-windows qt6:x64-windows \
    nlohmann-json:x64-windows gtest:x64-windows zlib:x64-windows
```

### Build Instructions

1. Clone the repository:
```bash
git clone https://github.com/your-org/encrypto-drive.git
cd encrypto-drive
```

2. Create build directory:
```bash
mkdir build && cd build
```

3. Configure with CMake:
```bash
# Linux/macOS
cmake .. -DCMAKE_BUILD_TYPE=Release

# Windows with vcpkg
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=[path to vcpkg]/scripts/buildsystems/vcpkg.cmake
```

4. Build:
```bash
# Linux/macOS
cmake --build . --config Release -j$(nproc)

# Windows
cmake --build . --config Release
```

5. Run tests:
```bash
ctest --output-on-failure
```

6. Install (optional):
```bash
# Linux/macOS
sudo cmake --install .

# Windows (run as administrator)
cmake --install .
```

### Running the Application

After building, you can run the application:

```bash
# GUI Application
./bin/encrypto-gui

# CLI Application
./bin/encrypto
```

### Troubleshooting

1. **CMake can't find Qt6:**
   ```bash
   cmake .. -DCMAKE_PREFIX_PATH=/path/to/qt6/lib/cmake
   ```

2. **OpenSSL not found:**
   ```bash
   cmake .. -DOPENSSL_ROOT_DIR=/path/to/openssl
   ```

3. **Build fails with compiler errors:**
   - Ensure you're using a C++17 compliant compiler
   - Try building in debug mode: `-DCMAKE_BUILD_TYPE=Debug`
   - Check the build log for specific error messages

4. **Tests fail:**
   - Run specific test suite: `./bin/encrypto-tests --gtest_filter="MerkleTreeTest.*"`
   - Enable verbose test output: `ctest -V`

## Usage Examples

### File Integrity Verification
```cpp
#include "core/integrity/merkletree.hpp"

// Create Merkle tree with FileIntegrity hasher
auto hasher = std::make_shared<FileIntegrity>();
MerkleTree tree(hasher);

// Add or update files
tree.updateNode("/path/to/file", fileData);

// Verify file integrity
bool isValid = tree.verifyPath("/path/to/file", fileData);

// Generate proof
auto proof = tree.getProof("/path/to/file");
```

### Version Control
```cpp
#include "core/version/versionstore.hpp"

// Create version store
VersionStore store("storage/dir", encryptionKey);

// Add file to version control
store.addFile("/path/to/file", "author", "Initial version");

// Create new version
store.createVersion("/path/to/file", "author", "Update description");

// Get version history
auto history = store.getHistory("/path/to/file");
```

### Digital Signatures
```cpp
#include "core/crypto/signaturesystem.hpp"

// Create signature system
SignatureSystem signatures;

// Generate key pair
auto keyPair = signatures.generateKeyPair();

// Sign data
auto signature = signatures.sign(data, keyPair.privateKey);

// Verify signature
bool isValid = signatures.verify(data, signature, keyPair.publicKey);
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

If you encounter any issues or need help:
1. Check the [Issues](https://github.com/your-org/encrypto-drive/issues) page
2. Create a new issue with detailed information about your problem
3. Include your build environment details and error messages
