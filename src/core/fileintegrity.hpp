#pragma once

#include "core/core_export.hpp"
#include <vector>
#include <string>
#include <cstdint>
#include <memory>

namespace encrypto::core {

/**
 * @brief File integrity verification using cryptographic hashes
 * 
 * Provides secure hash calculation and verification for files
 * using SHA-256 or BLAKE2b
 */
class ENCRYPTO_CORE_EXPORT FileIntegrity {
public:
    /**
     * @brief Hash algorithms available for integrity checks
     */
    enum class HashAlgorithm {
        SHA256,    // SHA-256 (default)
        BLAKE2b    // BLAKE2b-256
    };

    /**
     * @brief Constructor
     * @param algo Hash algorithm to use
     */
    explicit FileIntegrity(HashAlgorithm algo = HashAlgorithm::SHA256);

    /**
     * @brief Destructor
     */
    ~FileIntegrity();

    // Prevent copying
    FileIntegrity(const FileIntegrity&) = delete;
    FileIntegrity& operator=(const FileIntegrity&) = delete;

    /**
     * @brief Calculate hash of data
     * @param data Data to hash
     * @return Hash value or empty vector on failure
     */
    std::vector<uint8_t> calculateHash(const std::vector<uint8_t>& data);

    /**
     * @brief Calculate hash of file
     * @param filepath Path to file
     * @return Hash value or empty vector on failure
     */
    std::vector<uint8_t> calculateFileHash(const std::string& filepath);

    /**
     * @brief Verify data against hash
     * @param data Data to verify
     * @param hash Expected hash value
     * @return true if hash matches
     */
    bool verifyHash(const std::vector<uint8_t>& data,
                   const std::vector<uint8_t>& hash);

    /**
     * @brief Verify file against hash
     * @param filepath Path to file
     * @param hash Expected hash value
     * @return true if hash matches
     */
    bool verifyFileHash(const std::string& filepath,
                       const std::vector<uint8_t>& hash);

    /**
     * @brief Get current hash algorithm
     */
    HashAlgorithm getAlgorithm() const { return algorithm_; }

    /**
     * @brief Set hash algorithm
     * @param algo New algorithm to use
     */
    void setAlgorithm(HashAlgorithm algo);

    /**
     * @brief Get hash size in bytes for current algorithm
     */
    size_t getHashSize() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    HashAlgorithm algorithm_;
};

} // namespace encrypto::core
