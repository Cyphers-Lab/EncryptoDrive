#pragma once

#include "core/core_export.hpp"
#include "core/securememory.hpp"
#include "fileversion.hpp"
#include <filesystem>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <chrono>

namespace encrypto::core {

/**
 * @brief Version storage and management system
 *
 * Manages storage and retrieval of file versions using copy-on-write and
 * delta compression. Implements configurable version pruning policies.
 */
class ENCRYPTO_CORE_EXPORT VersionStore {
public:
    /**
     * @brief Version pruning policy
     */
    struct PruningPolicy {
        std::chrono::hours retentionPeriod{24 * 30}; // Keep 30 days by default
        size_t maxVersions{100};                      // Maximum versions to keep
        size_t minVersions{5};                        // Minimum versions to keep
        bool keepFirstVersion{true};                  // Always keep initial version
    };

    /**
     * @brief Constructor
     * @param storageDir Base directory for version storage
     * @param key Encryption key for version data
     */
    VersionStore(const std::string& storageDir,
                const SecureMemory::SecureVector<uint8_t>& key);

    /**
     * @brief Check if file is versioned
     * @param path File path
     * @return true if file is under version control
     */
    bool isVersioned(const std::string& path) const;

    /**
     * @brief Start version tracking for file
     * @param path File path
     * @param author Author identifier
     * @param description Initial version description
     * @return true if successful
     */
    bool addFile(const std::string& path,
                const std::string& author,
                const std::string& description = "Initial version");

    /**
     * @brief Create new version of file
     * @param path File path
     * @param author Author identifier
     * @param description Change description
     * @return Version number if successful
     */
    std::optional<size_t> createVersion(const std::string& path,
                                      const std::string& author,
                                      const std::string& description);

    /**
     * @brief Get version info for file
     * @param path File path
     * @param version Version number (latest if not specified)
     * @return Version info if exists
     */
    std::optional<FileVersion::VersionInfo> getVersionInfo(
        const std::string& path,
        std::optional<size_t> version = std::nullopt) const;

    /**
     * @brief Get file content for version
     * @param path File path
     * @param version Version number
     * @return File content if version exists
     */
    std::optional<std::vector<uint8_t>> getContent(
        const std::string& path,
        size_t version) const;

    /**
     * @brief Roll back file to previous version
     * @param path File path
     * @param version Version to restore
     * @param author Author identifier
     * @return true if rollback succeeded
     */
    bool rollback(const std::string& path,
                 size_t version,
                 const std::string& author);

    /**
     * @brief Apply pruning policy to file versions
     * @param path File path
     * @param policy Pruning policy to apply
     * @return Number of versions pruned
     */
    size_t pruneVersions(const std::string& path,
                        const PruningPolicy& policy);

    /**
     * @brief Get version history for file
     * @param path File path
     * @return Vector of version info
     */
    std::vector<FileVersion::VersionInfo> getHistory(
        const std::string& path) const;

    /**
     * @brief Save version store state
     * @return true if save succeeded
     */
    bool save() const;

private:
    std::filesystem::path storageDir_;
    const SecureMemory::SecureVector<uint8_t>& key_;
    std::unordered_map<std::string, std::unique_ptr<FileVersion>> versions_;

    // Helper methods
    std::filesystem::path getVersionPath(const std::string& path) const;
    bool loadVersion(const std::string& path);
    std::vector<uint8_t> readFile(const std::string& path) const;
    bool writeFile(const std::string& path,
                  const std::vector<uint8_t>& data) const;
    void loadVersions();
};

} // namespace encrypto::core
