#pragma once

#include "fs_export.hpp"
#include "../core/encryptionengine.hpp"
#include "../core/keysmanager.hpp"
#include <string>
#include <vector>
#include <optional>
#include "../core/compat/span.hpp"
#include <memory>
#include <filesystem>
#include <system_error>

namespace encrypto::fs {

namespace fs = std::filesystem;

/**
 * @brief Filesystem operation result
 */
struct ENCRYPTO_FS_EXPORT FsResult {
    bool success = false;
    std::error_code error;
    std::string message;
};

/**
 * @brief File metadata
 */
struct ENCRYPTO_FS_EXPORT FileMetadata {
    fs::path path;                      // Relative path within drive
    size_t size = 0;                    // Original file size
    std::vector<uint8_t> iv;           // Initialization vector
    std::vector<uint8_t> tag;          // Authentication tag
    std::filesystem::file_time_type modified;  // Last modified time
};

/**
 * @brief Encrypted filesystem operations
 */
class ENCRYPTO_FS_EXPORT FileSystem {
public:
    /**
     * @brief Constructor
     * @param encryption_engine Encryption engine to use
     * @param keys_manager Keys manager to use
     */
    FileSystem(std::shared_ptr<core::EncryptionEngine> encryption_engine,
               std::shared_ptr<core::KeysManager> keys_manager);

    /**
     * @brief Read file contents
     * @param path File path
     * @return Decrypted file contents or empty on error
     */
    std::vector<uint8_t> readFile(const fs::path& path);

    /**
     * @brief Write file contents
     * @param path File path
     * @param data File contents to encrypt and write
     * @return Operation result
     */
    FsResult writeFile(const fs::path& path, 
                      const std::vector<uint8_t>& data);

    /**
     * @brief Delete a file
     * @param path File path
     * @return Operation result
     */
    FsResult deleteFile(const fs::path& path);

    /**
     * @brief Get file metadata
     * @param path File path
     * @return Optional metadata or std::nullopt if file doesn't exist
     */
    std::optional<FileMetadata> getMetadata(const fs::path& path) const;

    /**
     * @brief Get file size
     * @param path File path
     * @return File size in bytes or 0 if file doesn't exist
     */
    size_t getFileSize(const fs::path& path) const;

    /**
     * @brief Check if file exists
     * @param path File path
     * @return true if file exists
     */
    bool exists(const fs::path& path) const;

    /**
     * @brief List directory contents
     * @param path Directory path
     * @return Vector of filenames or empty on error
     */
    std::vector<fs::path> listDirectory(const fs::path& path);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace encrypto::fs
