#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <memory>
#include <optional>
#include <filesystem>

namespace encrypto::keymanagement {

namespace fs = std::filesystem;

struct ShareLink {
    std::string id;                     // Unique share identifier
    std::string recipientId;            // Intended recipient's ID
    std::string encryptedKey;           // Encrypted file key
    std::vector<uint8_t> signature;     // Digital signature
    std::chrono::system_clock::time_point expires;  // Expiration timestamp
    bool offline;                       // Whether offline sharing is enabled
};

struct ShareMetadata {
    std::string id;
    std::string creatorId;
    std::string recipientId;
    fs::path resourcePath;
    std::chrono::system_clock::time_point created;
    std::chrono::system_clock::time_point expires;
    bool active;
    bool offline;
    std::vector<std::string> permissions;
};

struct PublicKey {
    std::string keyId;
    std::vector<uint8_t> keyData;
    std::string algorithm;
    std::chrono::system_clock::time_point created;
    std::optional<std::chrono::system_clock::time_point> expires;
};

class ShareProtocol {
public:
    explicit ShareProtocol(const std::string& configPath);
    ~ShareProtocol();

    /**
     * @brief Create a new share link
     * @param path Path to file/directory to share
     * @param recipientId Recipient's user ID
     * @param duration Share validity duration
     * @param offline Enable offline sharing
     * @return Share link if successful
     */
    std::optional<ShareLink> createShare(
        const fs::path& path, 
        const std::string& recipientId,
        std::chrono::seconds duration,
        bool offline = false);

    /**
     * @brief Verify recipient's identity and key
     * @param userId User ID to verify
     * @param key Public key to verify
     * @return true if recipient is verified
     */
    bool verifyRecipient(const std::string& userId, const PublicKey& key);

    /**
     * @brief Revoke an active share
     * @param shareId ID of share to revoke
     * @return true if share was revoked
     */
    bool revokeShare(const std::string& shareId);

    /**
     * @brief Get share metadata
     * @param shareId ID of share to query
     * @return Share metadata if found
     */
    std::optional<ShareMetadata> getShareInfo(const std::string& shareId);

    /**
     * @brief Accept a share invitation
     * @param shareId ID of share to accept
     * @param recipientKey Recipient's public key for verification
     * @return true if share was accepted
     */
    bool acceptShare(const std::string& shareId, const PublicKey& recipientKey);

    /**
     * @brief List all active shares
     * @return List of active share metadata
     */
    std::vector<ShareMetadata> listShares() const;

    /**
     * @brief Create an offline share package
     * @param shareId ID of share to package
     * @return Path to share package if successful
     */
    std::optional<fs::path> createOfflinePackage(const std::string& shareId);

    /**
     * @brief Import an offline share package
     * @param packagePath Path to share package
     * @param recipientKey Recipient's key for verification
     * @return Share metadata if import successful
     */
    std::optional<ShareMetadata> importOfflinePackage(
        const fs::path& packagePath, 
        const PublicKey& recipientKey);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;

    // Prevent copying
    ShareProtocol(const ShareProtocol&) = delete;
    ShareProtocol& operator=(const ShareProtocol&) = delete;
};

} // namespace encrypto::keymanagement
