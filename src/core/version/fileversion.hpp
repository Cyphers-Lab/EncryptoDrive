#pragma once

#include "core/core_export.hpp"
#include "core/securememory.hpp"
#include <string>
#include <vector>
#include <memory>
#include <ctime>
#include <optional>
#include <fstream>

namespace encrypto::core {

/**
 * @brief File version information and history tracking
 * 
 * Manages version metadata and content history for files, supporting
 * efficient storage and retrieval of file versions.
 */
class ENCRYPTO_CORE_EXPORT FileVersion {
public:
    /**
     * @brief Version metadata structure
     */
    struct VersionInfo {
        uint32_t version;       // Version number
        std::string author;     // Author identifier
        std::string description;// Change description
        std::time_t timestamp;  // Creation timestamp
    };

private:
    struct Version {
        uint32_t version;
        std::string author;
        std::string description;
        std::vector<uint8_t> content;
        std::optional<std::vector<uint8_t>> delta;
        std::time_t timestamp;
    };
    
    std::vector<Version> versions_;
    uint32_t currentVersion_ = 0;

    static std::vector<uint8_t> calculateDelta(const std::vector<uint8_t>& oldContent,
                                             const std::vector<uint8_t>& newContent);
    
    // Helper functions for file I/O
    static void writeString(std::ofstream& file, const std::string& str);
    static std::string readString(std::ifstream& file);
    static void writeVector(std::ofstream& file, const std::vector<uint8_t>& vec);
    static std::vector<uint8_t> readVector(std::ifstream& file);
    
    // Encryption helpers
    static std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data,
                                      const SecureMemory::SecureVector<uint8_t>& key);
    static std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data,
                                      const SecureMemory::SecureVector<uint8_t>& key);

public:
    /**
     * @brief Create empty version history
     */
    FileVersion() = default;

    /**
     * @brief Create version with initial content
     * @param data Initial file content
     * @param author Author identifier
     * @param description Change description
     */
    FileVersion(const std::vector<uint8_t>& data,
               const std::string& author,
               const std::string& description = "Initial version");

    /**
     * @brief Get current version number
     */
    uint32_t currentVersion() const;

    /**
     * @brief Get metadata for specific version
     * @param version Version number to query
     * @return Version metadata if exists
     */
    std::optional<VersionInfo> getVersionInfo(std::size_t version) const;

    /**
     * @brief Get content for specific version
     * @param version Version number to retrieve
     * @return Content if version exists
     */
    std::optional<std::vector<uint8_t>> getContent(std::size_t version) const;

    /**
     * @brief Create new version
     * @param newData New file content
     * @param author Author identifier
     * @param description Change description
     * @return Version number if successful
     */
    std::optional<uint32_t> createVersion(
        const std::vector<uint8_t>& newData,
        const std::string& author,
        const std::string& description);

    /**
     * @brief Roll back to previous version
     * @param version Version to restore
     * @return true if rollback succeeded
     */
    bool rollback(uint32_t version);

    /**
     * @brief Get changes between versions
     * @param fromVersion Start version
     * @param toVersion End version
     * @return Delta information if versions exist
     */
    std::optional<std::vector<uint8_t>> getDelta(
        uint32_t fromVersion,
        uint32_t toVersion) const;

    /**
     * @brief Save version history to encrypted file
     * @param filename Output filename 
     * @param key Encryption key
     * @return true if save succeeded
     */
    bool save(const std::string& filename,
             const SecureMemory::SecureVector<uint8_t>& key) const;

    /**
     * @brief Load version history from encrypted file
     * @param filename Input filename
     * @param key Decryption key
     * @return true if load succeeded
     */
    bool load(const std::string& filename,
             const SecureMemory::SecureVector<uint8_t>& key);
};

} // namespace encrypto::core
