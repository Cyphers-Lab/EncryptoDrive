#pragma once

#include "core/core_export.hpp"
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <filesystem>

namespace encrypto::core {

/**
 * @brief Manages encryption keys and their secure storage
 */
class ENCRYPTO_CORE_EXPORT KeysManager {
public:
    /**
     * @brief Constructor
     * @param keys_path Path to store encrypted keys
     */
    explicit KeysManager(std::filesystem::path keys_path);

    /**
     * @brief Destructor
     */
    ~KeysManager();

    // Prevent copying
    KeysManager(const KeysManager&) = delete;
    KeysManager& operator=(const KeysManager&) = delete;

    /**
     * @brief Initialize vault with master password
     * @param master_password Master password to encrypt vault
     * @return true if successful
     */
    bool initialize(std::string_view master_password);

    /**
     * @brief Unlock vault with master password
     * @param master_password Master password to decrypt vault
     * @return true if successful
     */
    bool unlock(std::string_view master_password);

    /**
     * @brief Lock vault and clear decrypted keys
     */
    void lock();

    /**
     * @brief Check if vault is unlocked
     * @return true if unlocked
     */
    bool isUnlocked() const;

    /**
     * @brief Change master password
     * @param old_password Current master password
     * @param new_password New master password to set
     * @return true if successful
     */
    bool changeMasterPassword(std::string_view old_password,
                            std::string_view new_password);

    /**
     * @brief Derive encryption key for a path
     * @param path Path to derive key for
     * @return Key bytes or empty if locked/error
     */
    std::vector<uint8_t> deriveKey(std::string_view path) const;

    /**
     * @brief Generate a new random key
     * @return Random key bytes or empty on error
     */
    std::vector<uint8_t> generateKey() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace encrypto::core
