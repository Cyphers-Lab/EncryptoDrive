#pragma once

#include "core_export.hpp"
#include "securememory.hpp"
#include <cstdint>
#include <string>
#include <chrono>
#include <memory>
#include <vector>
#include <optional>

namespace encrypto::core {

struct KeyVersion {
    uint64_t version;
    std::chrono::system_clock::time_point created;
    std::chrono::system_clock::time_point expires;
    SecureMemory::SecureVector<uint8_t> key;
    bool active;

    // Add move operations
    KeyVersion() = default;
    KeyVersion(KeyVersion&&) = default;
    KeyVersion& operator=(KeyVersion&&) = default;

    // Prevent copying
    KeyVersion(const KeyVersion&) = delete;
    KeyVersion& operator=(const KeyVersion&) = delete;
};

/**
 * @brief Manages key rotation and versioning
 * 
 * Handles secure key rotation, including:
 * - Version tracking
 * - Key expiration
 * - Automatic rotation scheduling
 * - Re-encryption with new keys
 */
class ENCRYPTO_CORE_EXPORT KeyRotation {
public:
    /**
     * @brief Rotation policy
     */
    enum class Policy {
        Manual,     // Manual rotation only
        Scheduled,  // Rotate on schedule
        Adaptive    // Adaptive based on usage/risk
    };

    /**
     * @brief Key usage metadata
     */
    struct KeyMetadata {
        uint64_t version;
        std::chrono::system_clock::time_point lastUsed;
        uint64_t usageCount;
        bool compromised;

        KeyMetadata() : version(0), usageCount(0), compromised(false) {}
    };

    /**
     * @brief Constructor
     * @param policy Rotation policy to use
     * @param interval Rotation interval in hours (default 90 days)
     */
    explicit KeyRotation(Policy policy = Policy::Manual,
                        std::chrono::hours interval = std::chrono::hours(24 * 90));

    /**
     * @brief Destructor
     */
    ~KeyRotation();

    // Prevent copying
    KeyRotation(const KeyRotation&) = delete;
    KeyRotation& operator=(const KeyRotation&) = delete;

    /**
     * @brief Get current active key version
     * @return Key version or nullopt if no active key
     */
    std::optional<KeyVersion> getCurrentKey() const;

    /**
     * @brief Get key by version
     * @param version Version to retrieve
     * @return Key version or nullopt if not found
     */
    std::optional<KeyVersion> getKeyVersion(uint64_t version) const;

    /**
     * @brief Add new key version
     * @param key Key data
     * @param expiry Optional expiry time
     * @return Version number of new key
     */
    uint64_t addKeyVersion(
        const SecureMemory::SecureVector<uint8_t>& key,
        std::chrono::system_clock::time_point expiry = 
            std::chrono::system_clock::time_point::max());

    /**
     * @brief Rotate to new key version
     * @param newKey Optional new key (generates random if not provided)
     * @return Version number of new key
     */
    uint64_t rotateKey(const SecureMemory::SecureVector<uint8_t>& newKey = 
                          SecureMemory::SecureVector<uint8_t>());

    /**
     * @brief Mark key version as compromised
     * @param version Version to mark
     */
    void markCompromised(uint64_t version);

    /**
     * @brief Check if key rotation is needed
     * @return true if rotation needed
     */
    bool needsRotation() const;

    /**
     * @brief Get key metadata
     * @param version Version to get metadata for
     * @return Metadata or nullopt if not found
     */
    std::optional<KeyMetadata> getKeyMetadata(uint64_t version) const;

    /**
     * @brief Update key usage metadata
     * @param version Version that was used
     */
    void updateUsage(uint64_t version);

    /**
     * @brief Get rotation policy
     */
    Policy getPolicy() const { return policy_; }

    /**
     * @brief Get rotation interval
     */
    std::chrono::hours getInterval() const { return rotationInterval_; }

    /**
     * @brief Set rotation policy
     * @param policy New policy
     * @param interval Optional new interval in hours (default 90 days)
     */
    void setPolicy(Policy policy, 
                  std::chrono::hours interval = std::chrono::hours(24 * 90));
                  
    /**
     * @brief Cleanup expired keys and associated metadata
     */
    void cleanupExpiredKeys();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    
    Policy policy_;
    std::chrono::hours rotationInterval_;
    
    bool shouldRotate() const;
    uint64_t generateNewVersion() const;
};

} // namespace encrypto::core
