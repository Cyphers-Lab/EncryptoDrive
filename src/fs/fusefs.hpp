#pragma once

#include "fs_export.hpp"
#include "fsops.hpp"
#include <memory>
#include <string>
#include <filesystem>

namespace encrypto::fs {

/**
 * @brief FUSE filesystem mount options
 */
struct ENCRYPTO_FS_EXPORT MountOptions {
    fs::path source_dir;       // Source directory to mount
    fs::path mount_point;      // Mount point directory
    bool read_only = false;    // Mount as read-only
    bool allow_other = false;  // Allow other users to access
    bool single_thread = false; // Run in single-threaded mode
};

/**
 * @brief FUSE filesystem implementation
 *
 * Provides encrypted filesystem interface using FUSE
 */
class ENCRYPTO_FS_EXPORT FuseFilesystem {
public:
    /**
     * @brief Constructor
     * @param fs Filesystem operations implementation
     */
    explicit FuseFilesystem(std::shared_ptr<FileSystem> fs);

    /**
     * @brief Destructor
     */
    ~FuseFilesystem();

    /**
     * @brief Mount the filesystem
     * @param options Mount options
     * @return true if successful
     */
    bool mount(const MountOptions& options);

    /**
     * @brief Unmount the filesystem
     * @return true if successful
     */
    bool unmount();

    /**
     * @brief Check if filesystem is mounted
     * @return true if mounted
     */
    bool isMounted() const;

    /**
     * @brief Get current mount point
     * @return Mount point path or empty if not mounted
     */
    fs::path getMountPoint() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace encrypto::fs
