#pragma once

#include "core/core_export.hpp"
#include "core/securememory.hpp"
#include <openssl/evp.h>
#include <memory>
#include <string>
#include <vector>
#include <optional>

namespace encrypto::core {

/**
 * @brief Digital signature system using EdDSA
 * 
 * Implements cryptographic signatures using Ed25519 with certificate
 * chain support for key validation.
 */
class ENCRYPTO_CORE_EXPORT SignatureSystem {
public:
    /**
     * @brief Key pair for signing operations
     */
    struct KeyPair {
        SecureMemory::SecureVector<uint8_t> privateKey;
        std::vector<uint8_t> publicKey;
    };

    /**
     * @brief Certificate information
     */
    struct Certificate {
        std::vector<uint8_t> publicKey;
        std::string subject;
        std::string issuer;
        time_t notBefore;
        time_t notAfter;
        std::vector<uint8_t> signature;
    };

    /**
     * @brief Constructor
     */
    SignatureSystem();

    /**
     * @brief Destructor
     */
    ~SignatureSystem();

    // Prevent copying
    SignatureSystem(const SignatureSystem&) = delete;
    SignatureSystem& operator=(const SignatureSystem&) = delete;

    /**
     * @brief Generate new key pair
     * @return Generated key pair
     */
    KeyPair generateKeyPair();

    /**
     * @brief Sign data with private key
     * @param data Data to sign
     * @param privateKey Private key for signing
     * @return Signature bytes or empty if failed
     */
    std::vector<uint8_t> sign(
        const std::vector<uint8_t>& data,
        const SecureMemory::SecureVector<uint8_t>& privateKey);

    /**
     * @brief Verify signature with public key
     * @param data Original data
     * @param signature Signature to verify
     * @param publicKey Public key for verification
     * @return true if signature is valid
     */
    bool verify(const std::vector<uint8_t>& data,
               const std::vector<uint8_t>& signature,
               const std::vector<uint8_t>& publicKey);

    /**
     * @brief Create certificate for public key
     * @param publicKey Public key to certify
     * @param subject Certificate subject
     * @param issuerKey Issuer's private key
     * @param issuerCert Issuer's certificate
     * @param validityDays Certificate validity period
     * @return Certificate if successful
     */
    std::optional<Certificate> createCertificate(
        const std::vector<uint8_t>& publicKey,
        const std::string& subject,
        const SecureMemory::SecureVector<uint8_t>& issuerKey,
        const Certificate& issuerCert,
        int validityDays = 365);

    /**
     * @brief Verify certificate chain
     * @param cert Certificate to verify
     * @param trustAnchors Trusted root certificates
     * @param intermediates Intermediate certificates in chain
     * @return true if chain is valid
     */
    bool verifyCertificateChain(
        const Certificate& cert,
        const std::vector<Certificate>& trustAnchors,
        const std::vector<Certificate>& intermediates = {});

    /**
     * @brief Export certificate to PEM format
     * @param cert Certificate to export
     * @return PEM string or empty if failed
     */
    std::string exportCertificatePEM(const Certificate& cert) const;

    /**
     * @brief Import certificate from PEM format
     * @param pem PEM string to import
     * @return Certificate if successful
     */
    std::optional<Certificate> importCertificatePEM(
        const std::string& pem) const;

    /**
     * @brief Export private key to encrypted PEM format
     * @param privateKey Private key to export
     * @param password Encryption password
     * @return Encrypted PEM string or empty if failed
     */
    std::string exportPrivateKeyPEM(
        const SecureMemory::SecureVector<uint8_t>& privateKey,
        const std::string& password) const;

    /**
     * @brief Import private key from encrypted PEM format
     * @param pem PEM string to import
     * @param password Decryption password
     * @return Private key if successful
     */
    std::optional<SecureMemory::SecureVector<uint8_t>> importPrivateKeyPEM(
        const std::string& pem,
        const std::string& password) const;

private:
    EVP_PKEY_CTX* ctx_;
    
    // Helper methods
    std::vector<uint8_t> serializeCertificate(const Certificate& cert) const;
    std::optional<Certificate> deserializeCertificate(
        const std::vector<uint8_t>& data) const;
    bool verifySignature(const std::vector<uint8_t>& data,
                        const std::vector<uint8_t>& signature,
                        EVP_PKEY* key) const;
};

} // namespace encrypto::core
