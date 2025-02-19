#pragma once

#include "fs_export.hpp"
#include <filesystem>
#include <vector>
#include <string>
#include <memory>

namespace encrypto::fs {

namespace fs = std::filesystem;

/**
 * @brief Secure file deletion patterns
 */
enum class DeletionPattern {
    ZERO,              // Single pass of zeros
    DOD_3PASS,        // DoD 5220.22-M (3 passes)
    DOD_7PASS,        // DoD 5220.22-M ECE (7 passes)
    GUTMANN,          // Peter Gutmann's 35-pass pattern
    RANDOM_3PASS      // 3 passes of random data
};

/**
 * @brief Result of secure deletion operation
 */
struct SecureDeleteResult {
    bool success;
    std::string error;
    bool trimIssued;      // Whether TRIM command was issued for SSDs
    bool verificationDone; // Whether verification was completed
};

/**
 * @brief Options for secure deletion
 */
struct SecureDeleteOptions {
    DeletionPattern pattern = DeletionPattern::DOD_3PASS;
    bool verify = true;           // Verify deletion
    bool handleBadSectors = true; // Attempt to handle bad sectors
    bool forceTrim = false;       // Force TRIM command even if not SSD
    bool retryOnError = true;     // Retry on write errors
    int maxRetries = 3;          // Maximum number of retries
};

/**
 * @brief Secure file deletion implementation
 */
class ENCRYPTO_FS_EXPORT SecureDelete {
public:
    SecureDelete();
    ~SecureDelete();

    /**
     * @brief Securely delete a file
     * @param path Path to file
     * @param options Deletion options
     * @return Result of deletion operation
     */
    SecureDeleteResult secureDelete(const fs::path& path, 
                                  const SecureDeleteOptions& options = {});

    /**
     * @brief Verify file deletion
     * @param path Path to deleted file
     * @return true if file is securely deleted
     */
    bool verifyDeletion(const fs::path& path);

    /**
     * @brief Check if device is SSD
     * @param path Path on device to check
     * @return true if path is on SSD
     */
    bool isSSD(const fs::path& path) const;

    /**
     * @brief Issue TRIM command for a file
     * @param path Path to file
     * @return true if TRIM command was issued
     */
    bool issueTrimCommand(const fs::path& path);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;

    // Prevent copying
    SecureDelete(const SecureDelete&) = delete;
    SecureDelete& operator=(const SecureDelete&) = delete;
};

} // namespace encrypto::fs
