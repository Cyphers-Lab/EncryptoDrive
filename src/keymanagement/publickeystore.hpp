#ifndef ENCRYPTO_PUBLICKEYSTORE_HPP
#define ENCRYPTO_PUBLICKEYSTORE_HPP

#include <vector>
#include <string>
#include <memory>
#include <chrono>
#include <optional>
#include <unordered_map>
#include <openssl/x509.h>

namespace encrypto {

/**
 * @brief Class managing public keys and trust relationships
 */
class PublicKeyStore {
public:
    struct UserKey {
        std::string userId;
        std::unique_ptr<X509, void(*)(X509*)> certificate;
        std::chrono::system_clock::time_point created;
        std::chrono::system_clock::time_point expires;
        bool revoked;
        std::string revocationReason;
    };

    struct TrustRelationship {
        std::string trusterId;
        std::string trusteeId;
        int trustLevel; // 0-100
        std::chrono::system_clock::time_point established;
        std::optional<std::chrono::system_clock::time_point> revoked;
    };

    /**
     * @brief Create a new PublicKeyStore instance
     * @param dbPath Path to the SQLite database file
     */
    explicit PublicKeyStore(const std::string& dbPath);
    ~PublicKeyStore();

    /**
     * @brief Add a new user key
     * @param userId Unique identifier for the user
     * @param cert X.509 certificate containing public key
     * @return true if added successfully
     */
    bool addUserKey(const std::string& userId, X509* cert);

    /**
     * @brief Get user's public key certificate
     * @param userId User identifier
     * @return Certificate pointer or nullptr if not found
     */
    X509* getUserKey(const std::string& userId) const;

    /**
     * @brief Revoke a user's key
     * @param userId User identifier
     * @param reason Reason for revocation
     * @return true if revoked successfully
     */
    bool revokeKey(const std::string& userId, const std::string& reason);

    /**
     * @brief Establish trust relationship between users
     * @param trusterId User granting trust
     * @param trusteeId User being trusted
     * @param level Trust level (0-100)
     * @return true if relationship established
     */
    bool establishTrust(const std::string& trusterId, 
                       const std::string& trusteeId,
                       int level);

    /**
     * @brief Revoke trust relationship
     * @param trusterId User revoking trust
     * @param trusteeId User trust being revoked from
     * @return true if relationship revoked
     */
    bool revokeTrust(const std::string& trusterId,
                     const std::string& trusteeId);

    /**
     * @brief Get trust level between users
     * @param trusterId User who granted trust
     * @param trusteeId User being trusted
     * @return Trust level or 0 if no relationship exists
     */
    int getTrustLevel(const std::string& trusterId,
                     const std::string& trusteeId) const;

    /**
     * @brief Check if a key is currently valid
     * @param userId User identifier
     * @return true if key exists and is valid
     */
    bool isKeyValid(const std::string& userId) const;

    /**
     * @brief Get all trust relationships for a user
     * @param userId User identifier
     * @return Vector of active trust relationships
     */
    std::vector<TrustRelationship> getUserTrustRelationships(
        const std::string& userId) const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;

    // Helper functions
    bool initializeDatabase();
    bool validateCertificate(X509* cert) const;
    void cleanupExpiredKeys();
};

} // namespace encrypto

#endif // ENCRYPTO_PUBLICKEYSTORE_HPP
