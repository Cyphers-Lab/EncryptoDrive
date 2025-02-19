#include "securedelete.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <linux/fs.h>
#include <cstring>
#include <cerrno>
#include <random>
#include <array>
#include <fstream>
#include <system_error>

namespace encrypto::fs {

namespace {
    // DoD 5220.22-M patterns
    const std::array<uint8_t, 3> DOD_3PASS_PATTERN = {0x00, 0xFF, 0x00};
    const std::array<uint8_t, 7> DOD_7PASS_PATTERN = {0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00};

    // Gutmann pattern (simplified version)
    const std::array<uint8_t, 35> GUTMANN_PATTERN = {
        0x00, 0xFF, 0x55, 0xAA, 0x00, 0xFF, 0x55, 0xAA,
        0x92, 0x49, 0x24, 0x92, 0x49, 0x24, 0x92, 0x49,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x92, 0x49, 0x24
    };

    // Buffer size for overwrites (1MB)
    constexpr size_t BUFFER_SIZE = 1024 * 1024;
}

class SecureDelete::Impl {
public:
    Impl() = default;

    SecureDeleteResult secureDelete(const fs::path& path, const SecureDeleteOptions& options) {
        SecureDeleteResult result{false, "", false, false};

        // Open file with sync flags
        int fd = open(path.c_str(), O_WRONLY | O_SYNC);
        if (fd == -1) {
            result.error = "Failed to open file: " + std::string(strerror(errno));
            return result;
        }

        // Get file size
        struct stat fileStat;
        if (fstat(fd, &fileStat) == -1) {
            close(fd);
            result.error = "Failed to get file size";
            return result;
        }

        // Check if file is on SSD
        bool isSsdDevice = isSSD(path);
        
        try {
            // Perform overwrites based on selected pattern
            switch (options.pattern) {
                case DeletionPattern::ZERO:
                    if (!overwriteFile(fd, fileStat.st_size, 0x00, options)) {
                        throw std::runtime_error("Zero overwrite failed");
                    }
                    break;

                case DeletionPattern::DOD_3PASS:
                    for (uint8_t pattern : DOD_3PASS_PATTERN) {
                        if (!overwriteFile(fd, fileStat.st_size, pattern, options)) {
                            throw std::runtime_error("DoD 3-pass overwrite failed");
                        }
                    }
                    break;

                case DeletionPattern::DOD_7PASS:
                    for (uint8_t pattern : DOD_7PASS_PATTERN) {
                        if (!overwriteFile(fd, fileStat.st_size, pattern, options)) {
                            throw std::runtime_error("DoD 7-pass overwrite failed");
                        }
                    }
                    break;

                case DeletionPattern::GUTMANN:
                    for (uint8_t pattern : GUTMANN_PATTERN) {
                        if (!overwriteFile(fd, fileStat.st_size, pattern, options)) {
                            throw std::runtime_error("Gutmann pattern overwrite failed");
                        }
                    }
                    break;

                case DeletionPattern::RANDOM_3PASS:
                    std::random_device rd;
                    std::mt19937 gen(rd());
                    std::uniform_int_distribution<> dis(0, 255);
                    
                    for (int i = 0; i < 3; ++i) {
                        if (!overwriteFile(fd, fileStat.st_size, static_cast<uint8_t>(dis(gen)), options)) {
                            throw std::runtime_error("Random overwrite failed");
                        }
                    }
                    break;
            }

            // Sync to ensure writes are committed
            fsync(fd);
            
            // Issue TRIM for SSDs
            if (isSsdDevice || options.forceTrim) {
                result.trimIssued = issueTrimCommand(fd, fileStat.st_size);
            }

            // Verify deletion if requested
            if (options.verify) {
                result.verificationDone = true;
                if (!verifyDeletion(fd, fileStat.st_size)) {
                    throw std::runtime_error("Verification failed");
                }
            }

            // Finally, unlink the file
            close(fd);
            if (unlink(path.c_str()) == -1) {
                throw std::runtime_error("Failed to unlink file");
            }

            result.success = true;
        } catch (const std::exception& e) {
            close(fd);
            result.error = e.what();
            return result;
        }

        return result;
    }

    bool verifyDeletion(const fs::path& path) {
        // Check if file exists
        if (fs::exists(path)) {
            return false;
        }

        // Try to open the file
        std::ifstream file(path, std::ios::binary);
        return !file.is_open();
    }

    bool isSSD(const fs::path& path) const {
        // Get the device name from path
        struct stat st;
        if (stat(path.c_str(), &st) == -1) {
            return false;
        }

        // Read from /sys/block/[device]/queue/rotational
        std::string device = getBlockDevice(st.st_dev);
        std::string rotational_path = "/sys/block/" + device + "/queue/rotational";
        
        std::ifstream rotational_file(rotational_path);
        if (!rotational_file) {
            return false;
        }

        std::string value;
        std::getline(rotational_file, value);
        
        // Return true if non-rotational (0 indicates SSD)
        return value.find('0') != std::string::npos;
    }

    bool issueTrimCommand(const fs::path& path) {
        int fd = open(path.c_str(), O_WRONLY);
        if (fd == -1) {
            return false;
        }

        bool result = issueTrimCommand(fd, fs::file_size(path));
        close(fd);
        return result;
    }

private:
    bool overwriteFile(int fd, off_t size, uint8_t pattern, const SecureDeleteOptions& options) {
        std::vector<uint8_t> buffer(BUFFER_SIZE, pattern);
        off_t remaining = size;
        
        while (remaining > 0) {
            size_t writeSize = std::min(static_cast<off_t>(BUFFER_SIZE), remaining);
            bool writeSuccess = false;
            int retries = 0;

            // Retry logic for bad sectors
            while (!writeSuccess && retries < options.maxRetries) {
                ssize_t written = write(fd, buffer.data(), writeSize);
                if (written == static_cast<ssize_t>(writeSize)) {
                    writeSuccess = true;
                } else if (written == -1) {
                    if (options.handleBadSectors && (errno == EIO || errno == ENOSPC)) {
                        // Try to skip bad sector
                        if (lseek(fd, BUFFER_SIZE, SEEK_CUR) == -1) {
                            return false;
                        }
                        retries++;
                    } else {
                        return false;
                    }
                } else {
                    // Partial write, adjust pointers
                    writeSize -= written;
                    remaining -= written;
                    if (lseek(fd, written, SEEK_CUR) == -1) {
                        return false;
                    }
                }
            }

            if (!writeSuccess) {
                return false;
            }

            remaining -= writeSize;
        }

        return true;
    }

    bool verifyDeletion(int fd, off_t size) {
        std::vector<uint8_t> buffer(BUFFER_SIZE);
        off_t remaining = size;

        if (lseek(fd, 0, SEEK_SET) == -1) {
            return false;
        }

        while (remaining > 0) {
            size_t readSize = std::min(static_cast<off_t>(BUFFER_SIZE), remaining);
            ssize_t bytesRead = read(fd, buffer.data(), readSize);
            
            if (bytesRead <= 0) {
                break;  // EOF or error
            }

            // Check if data was actually overwritten
            for (ssize_t i = 0; i < bytesRead; ++i) {
                if (buffer[i] != 0) {
                    return false;  // Found non-zero data
                }
            }

            remaining -= bytesRead;
        }

        return remaining <= 0;
    }

    bool issueTrimCommand(int fd, off_t length) {
        // Use FITRIM ioctl for SSDs
        struct fstrim_range range;
        range.start = 0;
        range.len = length;
        range.minlen = 0;

        return ioctl(fd, FITRIM, &range) == 0;
    }

    std::string getBlockDevice(dev_t dev) const {
        // Convert major/minor numbers to device name
        char devpath[256];
        snprintf(devpath, sizeof(devpath), "/sys/dev/block/%u:%u",
                major(dev), minor(dev));
        
        char resolvedpath[PATH_MAX];
        if (realpath(devpath, resolvedpath) == nullptr) {
            return "";
        }

        // Extract device name from path
        std::string path(resolvedpath);
        size_t pos = path.find_last_of('/');
        return pos != std::string::npos ? path.substr(pos + 1) : "";
    }
};

// Public interface implementation
SecureDelete::SecureDelete() : impl_(std::make_unique<Impl>()) {}
SecureDelete::~SecureDelete() = default;

SecureDeleteResult SecureDelete::secureDelete(const fs::path& path, 
                                            const SecureDeleteOptions& options) {
    return impl_->secureDelete(path, options);
}

bool SecureDelete::verifyDeletion(const fs::path& path) {
    return impl_->verifyDeletion(path);
}

bool SecureDelete::isSSD(const fs::path& path) const {
    return impl_->isSSD(path);
}

bool SecureDelete::issueTrimCommand(const fs::path& path) {
    return impl_->issueTrimCommand(path);
}

} // namespace encrypto::fs
