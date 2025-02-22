#include "keyrotation.hpp"
#include "encryptionengine.hpp"
#include <unordered_map>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <algorithm>
#include <stdexcept>

namespace encrypto::core {

class KeyRotation::Impl {
public:
    explicit Impl(Policy policy, std::chrono::hours interval)
        : lastRotation_(std::chrono::system_clock::now()),
          policy_(policy),
          rotationInterval_(interval) {}

    std::optional<KeyVersion> getCurrentKey() const {
        std::shared_lock lock(mutex_);
        for (const auto& kv : versions_) {
            if (kv.second.active) {
                // Create new KeyVersion and move data into it
                KeyVersion result;
                result.version = kv.second.version;
                result.created = kv.second.created;
                result.expires = kv.second.expires;
                result.key = SecureMemory::SecureVector<uint8_t>(kv.second.key.size());
                std::copy(kv.second.key.data(), 
                        kv.second.key.data() + kv.second.key.size(), 
                        result.key.data());
                result.active = kv.second.active;
                return std::optional<KeyVersion>(std::move(result));
            }
        }
        return std::nullopt;
    }

    std::optional<KeyVersion> getKeyVersion(uint64_t version) const {
        std::shared_lock lock(mutex_);
        auto it = versions_.find(version);
        if (it != versions_.end()) {
            // Create new KeyVersion and move data into it
            KeyVersion result;
            result.version = it->second.version;
            result.created = it->second.created;
            result.expires = it->second.expires;
            result.key = SecureMemory::SecureVector<uint8_t>(it->second.key.size());
            std::copy(it->second.key.data(), 
                    it->second.key.data() + it->second.key.size(), 
                    result.key.data());
            result.active = it->second.active;
            return std::optional<KeyVersion>(std::move(result));
        }
        return std::nullopt;
    }

    uint64_t addKeyVersion(const SecureMemory::SecureVector<uint8_t>& key,
                          std::chrono::system_clock::time_point expiry) {
        std::unique_lock lock(mutex_);
        uint64_t version = nextVersion_++;
        
        // Create new key version
        KeyVersion keyVer;
        keyVer.version = version;
        keyVer.created = std::chrono::system_clock::now();
        keyVer.expires = expiry;
        keyVer.key = SecureMemory::SecureVector<uint8_t>(key.size());
        std::copy(key.data(), key.data() + key.size(), keyVer.key.data());
        keyVer.active = true;
        
        // Deactivate current active key
        for (auto& kv : versions_) {
            kv.second.active = false;
        }
        
        versions_.emplace(version, std::move(keyVer));
        return version;
    }

    uint64_t rotateKey(const SecureMemory::SecureVector<uint8_t>& newKey) {
        // Generate new key if none provided
        SecureMemory::SecureVector<uint8_t> key;
        if (newKey.empty()) {
            EncryptionEngine engine;
            key = SecureMemory::SecureVector<uint8_t>(32); // 256 bits
            if (!engine.generateRandomBytes({key.data(), key.size()})) {
                throw std::runtime_error("Failed to generate random key");
            }
        } else {
            key = SecureMemory::SecureVector<uint8_t>(newKey.size());
            std::copy(newKey.data(), newKey.data() + newKey.size(), key.data());
        }

        // Calculate expiry based on policy
        auto now = std::chrono::system_clock::now();
        auto expiry = now + rotationInterval_;

        std::unique_lock lock(mutex_);
        lastRotation_ = now;
        return addKeyVersion(key, expiry);
    }

    void markCompromised(uint64_t version) {
        std::unique_lock lock(mutex_);
        auto it = metadata_.find(version);
        if (it != metadata_.end()) {
            it->second.compromised = true;
            // Also mark the key as inactive
            auto ver_it = versions_.find(version);
            if (ver_it != versions_.end()) {
                ver_it->second.active = false;
            }
        }
    }

    bool needsRotation() const {
        if (policy_ == Policy::Manual) {
            return false;
        }

        std::shared_lock lock(mutex_);
        auto now = std::chrono::system_clock::now();

        // Check for expired or compromised keys
        for (const auto& kv : versions_) {
            if (kv.second.active) {
                // Check expiry
                if (now >= kv.second.expires) {
                    return true;
                }
                
                // Check metadata
                auto meta_it = metadata_.find(kv.second.version);
                if (meta_it != metadata_.end()) {
                    const auto& meta = meta_it->second;
                    
                    // Check if compromised
                    if (meta.compromised) {
                        return true;
                    }
                    
                    // For adaptive policy, check usage patterns
                    if (policy_ == Policy::Adaptive) {
                        // Trigger rotation if key is heavily used
                        if (meta.usageCount > 1000000) { // Example threshold
                            return true;
                        }
                        
                        // Or if key hasn't been used in a while
                        auto unused_duration = now - meta.lastUsed;
                        if (unused_duration > rotationInterval_ * 2) {
                            return true;
                        }
                    }
                }
            }
        }

        // For scheduled policy, check rotation interval
        if (policy_ == Policy::Scheduled) {
            return (now - lastRotation_) >= rotationInterval_;
        }

        return false;
    }

    std::optional<KeyMetadata> getKeyMetadata(uint64_t version) const {
        std::shared_lock lock(mutex_);
        auto it = metadata_.find(version);
        if (it != metadata_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    void updateUsage(uint64_t version) {
        std::unique_lock lock(mutex_);
        auto& meta = metadata_[version];
        meta.version = version;
        meta.lastUsed = std::chrono::system_clock::now();
        meta.usageCount++;
    }

    void setPolicy(Policy policy, std::chrono::hours interval) {
        std::unique_lock lock(mutex_);
        policy_ = policy;
        rotationInterval_ = interval;
    }

    void cleanupExpiredKeys() {
        // Remove expired keys that aren't active
        auto now = std::chrono::system_clock::now();
        for (auto it = versions_.begin(); it != versions_.end();) {
            if (!it->second.active && now >= it->second.expires) {
                metadata_.erase(it->first);
                it = versions_.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    mutable std::shared_mutex mutex_;
    std::atomic<uint64_t> nextVersion_{1};
    std::unordered_map<uint64_t, KeyVersion> versions_;
    std::unordered_map<uint64_t, KeyMetadata> metadata_;
    std::chrono::system_clock::time_point lastRotation_;
    Policy policy_;
    std::chrono::hours rotationInterval_;
};

// Main class implementation delegating to Impl
KeyRotation::KeyRotation(Policy policy, std::chrono::hours interval)
    : impl_(std::make_unique<Impl>(policy, interval)),
      policy_(policy),
      rotationInterval_(interval) {}

KeyRotation::~KeyRotation() = default;

std::optional<KeyVersion> KeyRotation::getCurrentKey() const {
    return impl_->getCurrentKey();
}

std::optional<KeyVersion> KeyRotation::getKeyVersion(uint64_t version) const {
    return impl_->getKeyVersion(version);
}

uint64_t KeyRotation::addKeyVersion(
    const SecureMemory::SecureVector<uint8_t>& key,
    std::chrono::system_clock::time_point expiry) {
    return impl_->addKeyVersion(key, expiry);
}

uint64_t KeyRotation::rotateKey(const SecureMemory::SecureVector<uint8_t>& newKey) {
    return impl_->rotateKey(newKey);
}

void KeyRotation::markCompromised(uint64_t version) {
    impl_->markCompromised(version);
}

bool KeyRotation::needsRotation() const {
    return impl_->needsRotation();
}

std::optional<KeyRotation::KeyMetadata> KeyRotation::getKeyMetadata(uint64_t version) const {
    return impl_->getKeyMetadata(version);
}

void KeyRotation::updateUsage(uint64_t version) {
    impl_->updateUsage(version);
}

void KeyRotation::setPolicy(Policy policy, std::chrono::hours interval) {
    policy_ = policy;
    rotationInterval_ = interval;
    impl_->setPolicy(policy, interval);
}

bool KeyRotation::shouldRotate() const {
    return impl_->needsRotation();
}

void KeyRotation::cleanupExpiredKeys() {
    impl_->cleanupExpiredKeys();
}

uint64_t KeyRotation::generateNewVersion() const {
    static std::atomic<uint64_t> counter{1};
    return counter++;
}

} // namespace encrypto::core
