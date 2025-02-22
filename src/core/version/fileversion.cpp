#include "fileversion.hpp"
#include "../fileintegrity.hpp"
#include <zlib.h>
#include <algorithm>
#include <stdexcept>
#include <cassert>
#include <fstream>
#include <limits>
#include <cstring>

namespace encrypto::core {

namespace {

// Delta block size for efficient compression
constexpr size_t BLOCK_SIZE = 4096;

// Compresses data using zlib
static std::vector<uint8_t> compressData(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return {};
    }

    // Allocate compression buffer with zlib's recommended size
    uLongf compressedSize = compressBound(data.size());
    std::vector<uint8_t> compressed(compressedSize + 8); // Extra space for size header
    
    // Store original size at start of compressed data
    uint32_t originalSize = static_cast<uint32_t>(data.size());
    memcpy(compressed.data(), &originalSize, 4);
    uint32_t maxSize = static_cast<uint32_t>(compressedSize);
    memcpy(compressed.data() + 4, &maxSize, 4);
    
    // Compress the data
    if (compress2(compressed.data() + 8, &compressedSize,
                 data.data(), data.size(), 
                 Z_BEST_COMPRESSION) != Z_OK) {
        throw std::runtime_error("Compression failed");
    }

    compressed.resize(compressedSize + 8); // Include size header
    return compressed;
}

// Decompresses data using zlib
static std::vector<uint8_t> decompressData(
    const std::vector<uint8_t>& compressed,
    size_t /*unused*/) {
    if (compressed.size() < 8) {
        return {};
    }

    // Read size header
    uint32_t originalSize;
    uint32_t maxSize;
    memcpy(&originalSize, compressed.data(), 4);
    memcpy(&maxSize, compressed.data() + 4, 4);
    
    std::vector<uint8_t> decompressed(originalSize);
    uLongf decompressedSize = originalSize;

    if (uncompress(decompressed.data(), &decompressedSize,
                  compressed.data() + 8, compressed.size() - 8) != Z_OK) {
        throw std::runtime_error("Decompression failed");
    }

    assert(decompressedSize == originalSize);
    return decompressed;
}

} // anonymous namespace

FileVersion::FileVersion(const std::vector<uint8_t>& content,
                        const std::string& author,
                        const std::string& description) {
    versions_.push_back({
        0,  // Initial version
        author,
        description,
        content,
        std::nullopt,  // No delta for first version
        std::time(nullptr)  // Current timestamp
    });
}

std::optional<FileVersion::VersionInfo> FileVersion::getVersionInfo(std::size_t version) const {
    if (version >= versions_.size()) {
        return std::nullopt;
    }
    
    const auto& v = versions_[version];
    return VersionInfo{
        v.version,
        v.author,
        v.description,
        v.timestamp
    };
}

std::optional<std::vector<uint8_t>> FileVersion::getContent(std::size_t version) const {
    if (version > currentVersion_ || version >= versions_.size()) {
        return std::nullopt;
    }
    return versions_[version].content;
}

std::optional<uint32_t> FileVersion::createVersion(
    const std::vector<uint8_t>& content,
    const std::string& author,
    const std::string& description) {
    
    if (versions_.empty()) return std::nullopt;
    
    auto delta = calculateDelta(versions_[currentVersion_].content, content);
    uint32_t newVersion = currentVersion_ + 1;
    
    versions_.push_back({
        newVersion,
        author,
        description,
        content,
        delta,
        std::time(nullptr)  // Current timestamp
    });
    
    currentVersion_ = newVersion;
    return newVersion;
}

std::vector<uint8_t> FileVersion::calculateDelta(
    const std::vector<uint8_t>& oldContent,
    const std::vector<uint8_t>& newContent) {
    
    // Find common prefix and suffix
    size_t prefixLen = 0;
    const size_t minLen = std::min(oldContent.size(), newContent.size());
    
    while (prefixLen < minLen && oldContent[prefixLen] == newContent[prefixLen]) {
        prefixLen++;
    }
    
    size_t oldSuffixStart = oldContent.size();
    size_t newSuffixStart = newContent.size();
    
    while (oldSuffixStart > prefixLen && 
           newSuffixStart > prefixLen &&
           oldContent[oldSuffixStart-1] == newContent[newSuffixStart-1]) {
        oldSuffixStart--;
        newSuffixStart--;
    }
    
    // Create delta format:
    // [prefixLen:4][suffixLen:4][changedData]
    std::vector<uint8_t> delta;
    delta.reserve(8 + (newSuffixStart - prefixLen));
    
    // Write prefix length
    uint32_t prefix32 = static_cast<uint32_t>(prefixLen);
    delta.insert(delta.end(), 
                reinterpret_cast<uint8_t*>(&prefix32),
                reinterpret_cast<uint8_t*>(&prefix32) + 4);
                
    // Write changed data length
    uint32_t changed32 = static_cast<uint32_t>(newSuffixStart - prefixLen);
    delta.insert(delta.end(),
                reinterpret_cast<uint8_t*>(&changed32),
                reinterpret_cast<uint8_t*>(&changed32) + 4);
                
    // Write changed data
    if (newSuffixStart > prefixLen) {
        // Convert to signed to avoid sign conversion warning
        auto start = static_cast<std::vector<uint8_t>::difference_type>(prefixLen);
        auto end = static_cast<std::vector<uint8_t>::difference_type>(newSuffixStart);
        delta.insert(delta.end(),
                    newContent.begin() + start,
                    newContent.begin() + end);
    }
                
    // Compress the delta
    return compressData(delta);
}

bool FileVersion::save(const std::string& path, 
                      const SecureMemory::SecureVector<uint8_t>& key) const {
    try {
        std::ofstream file(path, std::ios::binary);
        if (!file) return false;

        // Write version count
        auto count = static_cast<uint32_t>(versions_.size());
        if (versions_.size() > std::numeric_limits<uint32_t>::max()) {
            return false;  // Too many versions to save
        }
        file.write(reinterpret_cast<const char*>(&count), sizeof(count));
        
        // Write current version
        file.write(reinterpret_cast<const char*>(&currentVersion_), sizeof(currentVersion_));

        // Write each version
        for (const auto& version : versions_) {
            // Compress and encrypt content
            auto compressedContent = compressData(version.content);
            auto encryptedContent = encrypt(compressedContent, key);
            
            // Write version data
            file.write(reinterpret_cast<const char*>(&version.version), sizeof(version.version));
            writeString(file, version.author);
            writeString(file, version.description);
            writeVector(file, encryptedContent);
            
            // Write delta if exists
            bool hasDelta = version.delta.has_value();
            file.write(reinterpret_cast<const char*>(&hasDelta), sizeof(hasDelta));
            if (hasDelta) {
                writeVector(file, encrypt(version.delta.value(), key));
            }
        }
        
        return true;
    } catch (...) {
        return false;
    }
}

bool FileVersion::load(const std::string& path, const SecureMemory::SecureVector<uint8_t>& key) {
    try {
        std::ifstream file(path, std::ios::binary);
        if (!file || !file.good()) {
            return false;
        }

        // Get file size
        file.seekg(0, std::ios::end);
        auto fileSize = file.tellg();
        file.seekg(0);
        
        // Basic file size validation
        if (fileSize < static_cast<std::streampos>(sizeof(uint32_t) * 2)) {
            return false;
        }

        // Read and validate header
        uint32_t count;
        if (!file.read(reinterpret_cast<char*>(&count), sizeof(count))) {
            return false;
        }
        
        // Basic sanity checks
        if (count == 0 || count > 10000) { // Reasonable max version limit
            return false;
        }

        // Read current version
        uint32_t currentVer;
        if (!file.read(reinterpret_cast<char*>(&currentVer), sizeof(currentVer)) ||
            currentVer >= count) {
            return false;
        }

        // Clear existing versions and prepare to load new ones
        versions_.clear();
        versions_.reserve(count);

        // Read each version
        for (uint32_t i = 0; i < count; ++i) {
            Version version;
            
            // Read and validate version number
            if (!file.read(reinterpret_cast<char*>(&version.version), sizeof(version.version)) ||
                version.version != i) {
                return false;
            }

            try {
                // Read metadata with size validation
                version.author = readString(file);
                if (version.author.empty()) return false;
                
                version.description = readString(file);
                if (version.description.empty()) return false;
                
                // Read and decompress content
                auto encryptedContent = readVector(file);
                if (encryptedContent.empty()) return false;
                
                auto decryptedContent = decrypt(encryptedContent, key);
                version.content = decompressData(decryptedContent, decryptedContent.size());
                if (version.content.empty()) return false;
                
                // Read delta if exists
                bool hasDelta;
                if (!file.read(reinterpret_cast<char*>(&hasDelta), sizeof(hasDelta))) {
                    return false;
                }
                
                if (hasDelta) {
                    auto encryptedDelta = readVector(file);
                    if (encryptedDelta.empty()) return false;
                    
                    auto decryptedDelta = decrypt(encryptedDelta, key);
                    version.delta = decompressData(decryptedDelta, decryptedDelta.size());
                    if (!version.delta || version.delta->empty()) return false;
                }
            } catch (...) {
                return false;
            }
            
            versions_.push_back(std::move(version));
        }
        
        currentVersion_ = currentVer;
        return file.peek() == EOF; // Ensure we read the whole file
    } catch (...) {
        return false;
    }
}

// Helper functions for file I/O
void FileVersion::writeString(std::ofstream& file, const std::string& str) {
    if (str.size() > std::numeric_limits<uint32_t>::max()) {
        throw std::runtime_error("String too large to write");
    }
    auto size = static_cast<uint32_t>(str.size());
    file.write(reinterpret_cast<const char*>(&size), sizeof(size));
    file.write(str.data(), static_cast<std::streamsize>(size));
}

std::string FileVersion::readString(std::ifstream& file) {
    uint32_t size;
    file.read(reinterpret_cast<char*>(&size), sizeof(size));
    std::string str(size, '\0');
    file.read(&str[0], size);
    return str;
}

void FileVersion::writeVector(std::ofstream& file, const std::vector<uint8_t>& vec) {
    if (vec.size() > std::numeric_limits<uint32_t>::max()) {
        throw std::runtime_error("Vector too large to write");
    }
    auto size = static_cast<uint32_t>(vec.size());
    file.write(reinterpret_cast<const char*>(&size), sizeof(size));
    file.write(reinterpret_cast<const char*>(vec.data()), 
               static_cast<std::streamsize>(size));
}

std::vector<uint8_t> FileVersion::readVector(std::ifstream& file) {
    uint32_t size;
    file.read(reinterpret_cast<char*>(&size), sizeof(size));
    std::vector<uint8_t> vec(size);
    file.read(reinterpret_cast<char*>(vec.data()), size);
    return vec;
}

// Encryption helpers (implement these according to your crypto system)
std::vector<uint8_t> FileVersion::encrypt(
    const std::vector<uint8_t>& data,
    const SecureMemory::SecureVector<uint8_t>& key) {
    // Simple XOR encryption for testing - in production this would use proper encryption
    std::vector<uint8_t> result(data);
    const uint8_t* keyData = key.data();
    size_t keySize = key.size();
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] ^= keyData[i % keySize];
    }
    return result;
}

std::vector<uint8_t> FileVersion::decrypt(
    const std::vector<uint8_t>& data,
    const SecureMemory::SecureVector<uint8_t>& key) {
    return encrypt(data, key); // XOR is symmetric
}

bool FileVersion::rollback(uint32_t version) {
    if (version >= versions_.size()) {
        return false;
    }
    // Remove all versions after the rollback point
    versions_.erase(versions_.begin() + version + 1, versions_.end());
    currentVersion_ = version;
    return true;
}

std::optional<std::vector<uint8_t>> FileVersion::getDelta(
    uint32_t fromVersion,
    uint32_t toVersion) const {
    if (fromVersion >= versions_.size() || toVersion >= versions_.size()) {
        return std::nullopt;
    }
    return versions_[toVersion].delta;
}

uint32_t FileVersion::currentVersion() const {
    return currentVersion_;
}

} // namespace encrypto::core
