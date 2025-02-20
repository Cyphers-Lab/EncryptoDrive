#include "fsops.hpp"
#include "fsconfig.hpp"
#include <fstream>
#include <mutex>

namespace encrypto::fs {

class FileSystem::Impl {
public:
    Impl(std::shared_ptr<core::EncryptionEngine> encryption_engine,
         std::shared_ptr<core::KeysManager> keys_manager)
        : encryption_engine_(std::move(encryption_engine))
        , keys_manager_(std::move(keys_manager)) {
    }

    std::vector<uint8_t> readFile(const fs::path& path) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!fs::exists(path)) {
            return {};
        }

        std::ifstream file(path, std::ios::binary);
        if (!file) {
            return {};
        }

        // Read header
        std::vector<uint8_t> iv(config::IV_SIZE);
        std::vector<uint8_t> tag(config::TAG_SIZE);
        uint64_t original_size;

        file.read(reinterpret_cast<char*>(iv.data()), iv.size());
        file.read(reinterpret_cast<char*>(tag.data()), tag.size());
        file.read(reinterpret_cast<char*>(&original_size), sizeof(original_size));

        if (!file) {
            return {};
        }

        // Read encrypted data
        std::vector<uint8_t> encrypted_data;
        encrypted_data.resize(fs::file_size(path) - 
                           (iv.size() + tag.size() + sizeof(original_size)));

        file.read(reinterpret_cast<char*>(encrypted_data.data()),
                 encrypted_data.size());

        if (!file) {
            return {};
        }

        // Get encryption key for this file
        auto key = keys_manager_->deriveKey(path.string());
        if (key.empty()) {
            return {};
        }

        // Convert to SecureVector
        core::SecureMemory::SecureVector<uint8_t> secure_key(key.begin(), key.end());
        core::SecureMemory::SecureVector<uint8_t> secure_tag(tag.begin(), tag.end());

        // Decrypt data
        auto decrypted = encryption_engine_->decrypt(
            secure_key,
            encrypted_data,
            secure_tag);

        if (decrypted.empty() || decrypted.size() != original_size) {
            return {};
        }

        return decrypted;
    }

    FsResult writeFile(const fs::path& path,
                      const std::vector<uint8_t>& data) {
        std::lock_guard<std::mutex> lock(mutex_);

        try {
            // Create parent directories if needed
            fs::create_directories(path.parent_path());

            // Generate IV
            std::vector<uint8_t> iv(config::IV_SIZE);
            if (!encryption_engine_->generateRandomBytes(
                    encrypto::core::compat::span<uint8_t>(iv))) {
                return {false, {}, "Failed to generate IV"};
            }

            // Get encryption key for this file
            auto key = keys_manager_->deriveKey(path.string());
            if (key.empty()) {
                return {false, {}, "Failed to derive key"};
            }

            // Convert to SecureVector
            core::SecureMemory::SecureVector<uint8_t> secure_key(key.begin(), key.end());
            core::SecureMemory::SecureVector<uint8_t> secure_tag(config::TAG_SIZE);

            // Encrypt data
            auto encrypted = encryption_engine_->encrypt(
                secure_key,
                data,
                secure_tag);

            // Convert tag back to vector for storage
            std::vector<uint8_t> tag(secure_tag.data(), secure_tag.data() + secure_tag.size());

            if (encrypted.empty()) {
                return {false, {}, "Encryption failed"};
            }

            // Write to file
            std::ofstream file(path, std::ios::binary | std::ios::trunc);
            if (!file) {
                return {false, {}, "Failed to open file for writing"};
            }

            // Write header: IV, TAG, original size
            const uint64_t original_size = data.size();

            file.write(reinterpret_cast<const char*>(iv.data()), iv.size());
            file.write(reinterpret_cast<const char*>(tag.data()), tag.size());
            file.write(reinterpret_cast<const char*>(&original_size),
                      sizeof(original_size));

            // Write encrypted data
            file.write(reinterpret_cast<const char*>(encrypted.data()),
                      encrypted.size());

            if (!file) {
                fs::remove(path);
                return {false, {}, "Failed to write file"};
            }

            return {true, {}, ""};
        }
        catch (const std::exception& e) {
            return {false, {}, e.what()};
        }
    }

    FsResult deleteFile(const fs::path& path) {
        std::lock_guard<std::mutex> lock(mutex_);

        try {
            if (!fs::remove(path)) {
                return {false, {}, "File does not exist"};
            }
            return {true, {}, ""};
        }
        catch (const std::exception& e) {
            return {false, {}, e.what()};
        }
    }

    std::optional<FileMetadata> getMetadata(const fs::path& path) const {
        std::lock_guard<std::mutex> lock(mutex_);

        try {
            if (!fs::exists(path)) {
                return std::nullopt;
            }

            FileMetadata metadata;
            metadata.path = path;
            metadata.modified = fs::last_write_time(path);

            if (fs::is_directory(path)) {
                metadata.size = 0;
                return metadata;
            }

            // Read header
            std::ifstream file(path, std::ios::binary);
            if (!file) {
                return std::nullopt;
            }

            // Read IV and tag
            metadata.iv.resize(config::IV_SIZE);
            metadata.tag.resize(config::TAG_SIZE);
            uint64_t original_size;

            file.read(reinterpret_cast<char*>(metadata.iv.data()),
                     metadata.iv.size());
            file.read(reinterpret_cast<char*>(metadata.tag.data()),
                     metadata.tag.size());
            file.read(reinterpret_cast<char*>(&original_size),
                     sizeof(original_size));

            if (!file) {
                return std::nullopt;
            }

            metadata.size = original_size;
            return metadata;
        }
        catch (const std::exception&) {
            return std::nullopt;
        }
    }

    size_t getFileSize(const fs::path& path) const {
        std::lock_guard<std::mutex> lock(mutex_);

        try {
            if (!fs::exists(path) || fs::is_directory(path)) {
                return 0;
            }

            std::ifstream file(path, std::ios::binary);
            if (!file) {
                return 0;
            }

            // Skip IV and tag
            file.seekg(config::IV_SIZE + config::TAG_SIZE);

            // Read original size
            uint64_t original_size;
            file.read(reinterpret_cast<char*>(&original_size),
                     sizeof(original_size));

            if (!file) {
                return 0;
            }

            return original_size;
        }
        catch (const std::exception&) {
            return 0;
        }
    }

    bool exists(const fs::path& path) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return fs::exists(path);
    }

    std::vector<fs::path> listDirectory(const fs::path& path) {
        std::lock_guard<std::mutex> lock(mutex_);

        std::vector<fs::path> entries;
        
        try {
            if (!fs::exists(path)) {
                return entries;
            }

            for (const auto& entry : fs::directory_iterator(path)) {
                entries.push_back(entry.path());
            }
        }
        catch (const std::exception&) {
            // Return empty vector on error
        }

        return entries;
    }

private:
    std::shared_ptr<core::EncryptionEngine> encryption_engine_;
    std::shared_ptr<core::KeysManager> keys_manager_;
    mutable std::mutex mutex_;
};

// Public interface implementation
FileSystem::FileSystem(std::shared_ptr<core::EncryptionEngine> encryption_engine,
                      std::shared_ptr<core::KeysManager> keys_manager)
    : impl_(std::make_unique<Impl>(std::move(encryption_engine),
                                  std::move(keys_manager))) {
    }

FileSystem::~FileSystem() = default;

std::vector<uint8_t> FileSystem::readFile(const fs::path& path) {
    return impl_->readFile(path);
}

FsResult FileSystem::writeFile(const fs::path& path,
                             const std::vector<uint8_t>& data) {
    return impl_->writeFile(path, data);
}

FsResult FileSystem::deleteFile(const fs::path& path) {
    return impl_->deleteFile(path);
}

std::optional<FileMetadata> FileSystem::getMetadata(const fs::path& path) const {
    return impl_->getMetadata(path);
}

size_t FileSystem::getFileSize(const fs::path& path) const {
    return impl_->getFileSize(path);
}

bool FileSystem::exists(const fs::path& path) const {
    return impl_->exists(path);
}

std::vector<fs::path> FileSystem::listDirectory(const fs::path& path) {
    return impl_->listDirectory(path);
}

} // namespace encrypto::fs
