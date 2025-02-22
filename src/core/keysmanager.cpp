#include "keysmanager.hpp"
#include "encryptionengine.hpp"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <fstream>
#include <mutex>
#include <unordered_map>
#include <cstring>

namespace encrypto::core {

namespace {

// Constants for key derivation
constexpr size_t MASTER_KEY_SIZE = 32;  // 256 bits
constexpr size_t SALT_SIZE = 32;        // 256 bits
constexpr int PBKDF2_ITERATIONS = 100000;

// Vault file format:
// [SALT (32 bytes)][TAG (16 bytes)][ENCRYPTED DATA (IV + VAULT)]

SecureMemory::SecureVector<uint8_t> deriveKey(std::string_view password,
                             const std::vector<uint8_t>& salt) {
    SecureMemory::SecureVector<uint8_t> key(MASTER_KEY_SIZE);

    if (PKCS5_PBKDF2_HMAC_SHA1(
            password.data(),
            static_cast<int>(password.length()),
            reinterpret_cast<const unsigned char*>(salt.data()),
            static_cast<int>(salt.size()),
            PBKDF2_ITERATIONS,
            static_cast<int>(key.size()),
            reinterpret_cast<unsigned char*>(key.data())) != 1) {
        return {};
    }
    return key;
}

} // namespace

class KeysManager::Impl {
public:
    explicit Impl(std::filesystem::path keys_path)
        : keys_path_(std::move(keys_path))
        , engine_(std::make_unique<EncryptionEngine>())
        , master_key_(MASTER_KEY_SIZE)
        , vault_data_(0)
        , tag_buffer_(16)
        , unlocked_(false)
        , mutex_() {
    }

    bool initialize(std::string_view master_password) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (std::filesystem::exists(keys_path_)) {
            return false;
        }

        try {
            // Create parent directories if needed
            std::filesystem::create_directories(keys_path_.parent_path());

            // Generate salt
            std::vector<uint8_t> salt(SALT_SIZE);
            if (!engine_->generateRandomBytes(compat::span<uint8_t>(salt.data(), salt.size()))) {
                return false;
            }

            // Generate master key using the namespace deriveKey function
            master_key_ = ::encrypto::core::deriveKey(master_password, salt);

            // Initialize empty vault
            std::vector<uint8_t> empty_vault;
            auto encrypted = engine_->encrypt(master_key_, empty_vault, tag_buffer_);
            if (encrypted.empty()) {
                return false;
            }

            // Write vault file
            std::ofstream file(keys_path_, std::ios::binary);
            if (!file) {
                return false;
            }

            file.write(reinterpret_cast<const char*>(salt.data()), 
                      static_cast<std::streamsize>(salt.size()));
            file.write(reinterpret_cast<const char*>(tag_buffer_.data()), 
                      static_cast<std::streamsize>(tag_buffer_.size()));
            file.write(reinterpret_cast<const char*>(encrypted.data()),
                      static_cast<std::streamsize>(encrypted.size()));

            if (!file) {
                std::filesystem::remove(keys_path_);
                return false;
            }

            unlocked_ = true;
            return true;
        }
        catch (const std::exception&) {
            return false;
        }
    }

    bool unlock(std::string_view master_password) {
        std::lock_guard<std::mutex> lock(mutex_);

        try {
            // Open vault file
            std::ifstream file(keys_path_, std::ios::binary);
            if (!file) {
                return false;
            }

            // Read salt
            std::vector<uint8_t> salt(SALT_SIZE);
            file.read(reinterpret_cast<char*>(salt.data()), 
                     static_cast<std::streamsize>(salt.size()));

            // Read authentication tag
            file.read(reinterpret_cast<char*>(tag_buffer_.data()), 
                     static_cast<std::streamsize>(tag_buffer_.size()));

            // Read encrypted data (includes IV)
            std::vector<uint8_t> encrypted;
            encrypted.resize(std::filesystem::file_size(keys_path_) -
                           (salt.size() + tag_buffer_.size()));

            file.read(reinterpret_cast<char*>(encrypted.data()),
                     static_cast<std::streamsize>(encrypted.size()));

            if (!file) {
                return false;
            }

            // Derive master key using the namespace deriveKey function
            master_key_ = ::encrypto::core::deriveKey(master_password, salt);

            // Decrypt vault with authentication (IV is included in encrypted data)
            auto decrypted = engine_->decrypt(master_key_, encrypted, tag_buffer_);
            if (decrypted.empty()) {
                master_key_.clear();
                return false;
            }

            vault_data_ = SecureMemory::SecureVector<uint8_t>(decrypted.size());
            std::memcpy(vault_data_.data(), decrypted.data(), decrypted.size());
            
            unlocked_ = true;
            return true;
        }
        catch (const std::exception&) {
            return false;
        }
    }

    void lock() {
        std::lock_guard<std::mutex> lock(mutex_);
        master_key_.clear();
        vault_data_.clear();
        unlocked_ = false;
    }

    bool isUnlocked() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return unlocked_;
    }

    bool changeMasterPassword([[maybe_unused]] std::string_view old_password,
                            std::string_view new_password) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!unlocked_) {
            return false;
        }

        // Generate new salt
        std::vector<uint8_t> new_salt(SALT_SIZE);
        if (!engine_->generateRandomBytes(compat::span<uint8_t>(new_salt.data(), new_salt.size()))) {
            return false;
        }

        // Generate new master key using the namespace deriveKey function
        auto new_key = ::encrypto::core::deriveKey(new_password, new_salt);

        // Convert secure vault data to vector for encryption
        std::vector<uint8_t> temp_vault(vault_data_.size());
        std::memcpy(temp_vault.data(), vault_data_.data(), vault_data_.size());
        
        auto encrypted = engine_->encrypt(new_key, temp_vault, tag_buffer_);
        if (encrypted.empty()) {
            return false;
        }

        // Write new vault file
        std::ofstream file(keys_path_, std::ios::binary | std::ios::trunc);
        if (!file) {
            return false;
        }

        file.write(reinterpret_cast<const char*>(new_salt.data()),
                  static_cast<std::streamsize>(new_salt.size()));
        file.write(reinterpret_cast<const char*>(tag_buffer_.data()),
                  static_cast<std::streamsize>(tag_buffer_.size()));
        file.write(reinterpret_cast<const char*>(encrypted.data()),
                  static_cast<std::streamsize>(encrypted.size()));

        if (!file) {
            return false;
        }

        master_key_ = std::move(new_key);
        return true;
    }

    std::vector<uint8_t> deriveKey(std::string_view path) const {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!unlocked_) {
            return {};
        }

        // Use EVP_MAC (HMAC-SHA256) to derive a unique key for this path
        std::vector<uint8_t> derived(SHA256_DIGEST_LENGTH);
        
        EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
        if (!mac) {
            return {};
        }
        
        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
        if (!ctx) {
            EVP_MAC_free(mac);
            return {};
        }
        
        OSSL_PARAM params[] = {
            OSSL_PARAM_utf8_string("digest", const_cast<char*>("SHA256"), sizeof("SHA256")),
            OSSL_PARAM_END
        };
        
        bool success = false;
        size_t out_len = 0;
        
        if (EVP_MAC_init(ctx, master_key_.data(), master_key_.size(), params) == 1) {
            success = EVP_MAC_update(ctx, reinterpret_cast<const uint8_t*>(path.data()), path.length()) == 1 &&
                     EVP_MAC_final(ctx, derived.data(), &out_len, derived.size()) == 1;
        }
        
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        
        if (!success) {
            return {};
        }
        
        return derived;
    }

    std::vector<uint8_t> generateKey() const {
        if (!unlocked_) {
            return {};
        }

        std::vector<uint8_t> key(MASTER_KEY_SIZE);
        if (!engine_->generateRandomBytes(compat::span<uint8_t>(key.data(), key.size()))) {
            return {};
        }

        return key;
    }

private:
    std::filesystem::path keys_path_;
    std::unique_ptr<EncryptionEngine> engine_;
    SecureMemory::SecureVector<uint8_t> master_key_;
    SecureMemory::SecureVector<uint8_t> vault_data_;
    SecureMemory::SecureVector<uint8_t> tag_buffer_;
    bool unlocked_;
    mutable std::mutex mutex_;
};

// Public interface implementation
KeysManager::KeysManager(std::filesystem::path keys_path)
    : impl_(std::make_unique<Impl>(std::move(keys_path))) {
}

KeysManager::~KeysManager() = default;

bool KeysManager::initialize(std::string_view master_password) {
    return impl_->initialize(master_password);
}

bool KeysManager::unlock(std::string_view master_password) {
    return impl_->unlock(master_password);
}

void KeysManager::lock() {
    impl_->lock();
}

bool KeysManager::isUnlocked() const {
    return impl_->isUnlocked();
}

bool KeysManager::changeMasterPassword(std::string_view old_password,
                                     std::string_view new_password) {
    return impl_->changeMasterPassword(old_password, new_password);
}

std::vector<uint8_t> KeysManager::deriveKey(std::string_view path) const {
    return impl_->deriveKey(path);
}

std::vector<uint8_t> KeysManager::generateKey() const {
    return impl_->generateKey();
}

} // namespace encrypto::core
