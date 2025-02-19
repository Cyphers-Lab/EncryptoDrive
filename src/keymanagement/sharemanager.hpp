#ifndef ENCRYPTO_SHAREMANAGER_HPP
#define ENCRYPTO_SHAREMANAGER_HPP

#include <vector>
#include <string>
#include <memory>
#include <chrono>
#include <optional>
#include <unordered_map>
#include <openssl/evp.h>

namespace encrypto {

class ShareManager {
public:
    struct AccessControl {
        std::string userId;
        std::vector<std::string> permissions;
        std::chrono::system_clock::time_point expires;
        bool revoked;
    };

    struct EphemeralKey {
        std::vector<uint8_t> keyData;
        std::chrono::system_clock::time_point created;
        std::chrono::system_clock::time_point expires;
        std::string purpose;
        bool consumed;
    };

    /**
     * @brief Create a new ShareManager instance
     * @param dbPath Path to the SQLite database file
     */
    explicit ShareManager(const std::string& dbPath);
    ~ShareManager();

    /**
     * @brief Grant access to a user
     * @param userId User to grant access to
     * @param permissions List of permission strings
     * @param duration Duration for which access is valid
     * @return true if access granted successfully
     */
    bool grantAccess(const std::string& userId,
                     const std::vector<std::string>& permissions,
                     std::chrono::seconds duration);

    /**
     * @brief Revoke access from a user
     * @param userId User to revoke access from
     * @return true if access revoked successfully
     */
    bool revokeAccess(const std::string& userId);

    /**
     * @brief Check if user has specific permission
     * @param userId User to check
     * @param permission Permission to verify
     * @return true if user has permission
     */
    bool hasPermission(const std::string& userId,
                      const std::string& permission) const;

    /**
     * @brief Generate a new ephemeral key
     * @param purpose Purpose identifier for the key
     * @param lifetime How long the key should be valid
     * @return Key ID if successful, empty optional otherwise
     */
    std::optional<std::string> generateEphemeralKey(
        const std::string& purpose,
        std::chrono::seconds lifetime);

    /**
     * @brief Consume an ephemeral key
     * @param keyId ID of the key to consume
     * @return Key data if available and unused, empty vector otherwise
     */
    std::vector<uint8_t> consumeEphemeralKey(const std::string& keyId);

    /**
     * @brief Get all active access controls for a user
     * @param userId User ID to look up
     * @return Vector of active access controls
     */
    std::vector<AccessControl> getUserAccess(const std::string& userId) const;

    /**
     * @brief Get all valid ephemeral keys for a purpose
     * @param purpose Purpose to filter by
     * @return Vector of valid, unconsumed keys
     */
    std::vector<std::pair<std::string, EphemeralKey>> 
    getValidEphemeralKeys(const std::string& purpose) const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;

    // Helper methods
    bool initializeDatabase();
    void cleanupExpiredEntries();
    std::vector<uint8_t> generateSecureRandomBytes(size_t length) const;
};

} // namespace encrypto

#endif // ENCRYPTO_SHAREMANAGER_HPP
