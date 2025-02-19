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
- C++17 compliant compiler
- CMake 3.15 or higher
- OpenSSL development libraries
- libsodium development libraries
- Google Test framework (for testing)

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
cmake ..
```

4. Build:
```bash
cmake --build .
```

5. Run tests:
```bash
ctest --output-on-failure
```

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

## Testing

The project includes comprehensive unit tests for all components. Tests are written using Google Test framework and can be found in the `tests/` directory.

To run specific test suites:
```bash
./bin/encrypto-tests --gtest_filter="MerkleTreeTest.*"
./bin/encrypto-tests --gtest_filter="FileVersionTest.*"
./bin/encrypto-tests --gtest_filter="SignatureSystemTest.*"
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
