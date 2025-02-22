#pragma once

#include "core/core_export.hpp"
#include "core/compat/span.hpp"
#include "core/fileintegrity.hpp"
#include "core/securememory.hpp"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <vector>
#include <cstdint>
#include <string>
#include <memory>

namespace encrypto::core {

/**
 * @brief Available encryption algorithms
 */
enum class Algorithm {
    AES_256_GCM,      // AES-256 in GCM mode (default)
    CHACHA20_POLY1305,// ChaCha20 with Poly1305 MAC
    XCHACHA20_POLY1305// XChaCha20 with Poly1305 MAC (extended nonce)
};

/**
 * @brief Encryption engine for cryptographic operations
 * 
 * Provides secure encryption/decryption using multiple algorithms
 */
class ENCRYPTO_CORE_EXPORT EncryptionEngine {
public:
    /**
     * @brief Encryption parameters for customizing encryption behavior
     */
    struct EncryptionParams {
        size_t kdf_iterations = 100000;  // Number of iterations for key derivation
        size_t memory_cost = 65536;      // Memory cost for Argon2
        uint32_t parallelism = 4;        // Parallelism factor for Argon2
        std::string salt;                // Optional salt for key derivation
    };

    /**
     * @brief Constructor
     * @param algo Encryption algorithm to use (defaults to AES-256-GCM)
     */
    explicit EncryptionEngine(Algorithm algo = Algorithm::AES_256_GCM);

    /**
     * @brief Destructor
     */
    ~EncryptionEngine();

    // Prevent copying
    EncryptionEngine(const EncryptionEngine&) = delete;
    EncryptionEngine& operator=(const EncryptionEngine&) = delete;

    /**
     * @brief Set encryption algorithm
     * @param algo New algorithm to use
     * @return true if algorithm was changed successfully
     */
    bool setAlgorithm(Algorithm algo);

    /**
     * @brief Get current encryption algorithm
     */
    Algorithm getAlgorithm() const;

    /**
     * @brief Get algorithm name as string
     */
    static std::string algorithmToString(Algorithm algo);

    /**
     * @brief Set encryption parameters
     * @param params New parameters to use
     */
    void setParams(const EncryptionParams& params);

    /**
     * @brief Get current encryption parameters
     */
    const EncryptionParams& getParams() const;

    /**
     * @brief Encrypt data using selected algorithm
     * @param key Encryption key
     * @param data Data to encrypt
     * @param tag Output authentication tag
     * @return Encrypted data (includes IV) or empty on failure
     */
    SecureMemory::SecureVector<uint8_t> encrypt(
        const SecureMemory::SecureVector<uint8_t>& key,
        const std::vector<uint8_t>& data,
        SecureMemory::SecureVector<uint8_t>& tag);

    /**
     * @brief Decrypt data using selected algorithm
     * @param key Decryption key
     * @param data Data to decrypt 
     * @param tag Authentication tag
     * @return Decrypted data or empty on failure
     */
    std::vector<uint8_t> decrypt(
        const SecureMemory::SecureVector<uint8_t>& key,
        const std::vector<uint8_t>& data,
        const SecureMemory::SecureVector<uint8_t>& tag);

    /**
     * @brief Generate random bytes
     * @param output Buffer to fill with random bytes
     * @return true if successful
     */
    bool generateRandomBytes(compat::span<uint8_t> output);

    /**
     * @brief Get file integrity verifier
     * @return File integrity instance
     */
    FileIntegrity& getIntegrityVerifier() { return *integrityVerifier_; }

private:
    EVP_CIPHER_CTX* ctx_;
    Algorithm currentAlgo_;
    EncryptionParams params_;
    std::unique_ptr<FileIntegrity> integrityVerifier_;
    
    const EVP_CIPHER* getCipher() const;
    bool initializeContext();

    // Helper method to calculate and append integrity hash
    SecureMemory::SecureVector<uint8_t> appendIntegrityHash(
        const SecureMemory::SecureVector<uint8_t>& data);
    
    // Helper method to verify and strip integrity hash
    bool verifyAndStripIntegrityHash(SecureMemory::SecureVector<uint8_t>& data);

    // Key derivation function wrapper
    SecureMemory::SecureVector<uint8_t> deriveKey(
        const SecureMemory::SecureString& password,
        const std::string& salt) const;
};

} // namespace encrypto::core
