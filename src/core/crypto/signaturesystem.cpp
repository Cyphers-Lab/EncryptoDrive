#include "signaturesystem.hpp"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <algorithm>
#include <sstream>
#include <iostream>
#include <cstring>
#include <cassert>
#include <limits>
#include <set>
#include <memory>
#include <ctime>
#include <optional>
#include <functional>
#include <cstdint>

namespace {

// Buffer size for PEM operations
constexpr size_t BUFFER_SIZE = 4096;

// Ed25519 key sizes
constexpr size_t ED25519_PRIVATE_KEY_SIZE = 32;
constexpr size_t ED25519_PUBLIC_KEY_SIZE = 32;
constexpr size_t ED25519_SIGNATURE_SIZE = 64;

// Maximum string length for subject/issuer
constexpr size_t MAX_STRING_LENGTH = 255;

// Convert OpenSSL error to string
std::string getOpenSSLError() {
    char buf[256];
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return buf;
}

} // anonymous namespace

namespace encrypto::core {

SignatureSystem::SignatureSystem() : ctx_(nullptr) {
    ctx_ = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!ctx_) {
        throw std::runtime_error("Failed to create EdDSA context: " + getOpenSSLError());
    }
}

SignatureSystem::~SignatureSystem() {
    if (ctx_) {
        EVP_PKEY_CTX_free(ctx_);
    }
}

SignatureSystem::KeyPair SignatureSystem::generateKeyPair() {
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen_init(ctx_) <= 0 ||
        EVP_PKEY_keygen(ctx_, &pkey) <= 0) {
        throw std::runtime_error("Failed to generate key pair: " + getOpenSSLError());
    }
    
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> keyGuard(pkey, EVP_PKEY_free);

    // Extract private key
    size_t privLen = ED25519_PRIVATE_KEY_SIZE;
    SecureMemory::SecureVector<uint8_t> privateKey(privLen);
    if (EVP_PKEY_get_raw_private_key(pkey, privateKey.data(), &privLen) <= 0) {
        throw std::runtime_error("Failed to extract private key: " + getOpenSSLError());
    }

    // Extract public key
    size_t pubLen = ED25519_PUBLIC_KEY_SIZE;
    std::vector<uint8_t> publicKey(pubLen);
    if (EVP_PKEY_get_raw_public_key(pkey, publicKey.data(), &pubLen) <= 0) {
        throw std::runtime_error("Failed to extract public key: " + getOpenSSLError());
    }

    return KeyPair{std::move(privateKey), std::move(publicKey)};
}

std::vector<uint8_t> SignatureSystem::sign(
    const std::vector<uint8_t>& data,
    const SecureMemory::SecureVector<uint8_t>& privateKey) {
    
    // Create key from raw private key
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr,
        privateKey.data(), privateKey.size());
    if (!pkey) {
        return {};
    }
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> keyGuard(pkey, EVP_PKEY_free);

    // Create signing context
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        return {};
    }
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> 
        ctxGuard(mdctx, EVP_MD_CTX_free);

    // Sign data
    if (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey) <= 0) {
        return {};
    }

    size_t sigLen = ED25519_SIGNATURE_SIZE;
    std::vector<uint8_t> signature(sigLen);

    if (EVP_DigestSign(mdctx,
                      signature.data(), &sigLen,
                      data.data(), data.size()) <= 0) {
        return {};
    }

    signature.resize(sigLen);
    return signature;
}

bool SignatureSystem::verify(
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& publicKey) {
    
    // Create key from raw public key
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr,
        publicKey.data(), publicKey.size());
    if (!pkey) {
        return false;
    }
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> keyGuard(pkey, EVP_PKEY_free);

    return verifySignature(data, signature, pkey);
}

std::optional<SignatureSystem::Certificate> SignatureSystem::createCertificate(
    const std::vector<uint8_t>& publicKey,
    const std::string& subject,
    const SecureMemory::SecureVector<uint8_t>& issuerKey,
    const Certificate& issuerCert,
    int validityDays) {

    try {
        // Early validation of inputs
        if (subject.empty() || subject.length() > MAX_STRING_LENGTH || 
            publicKey.empty() || publicKey.size() != ED25519_PUBLIC_KEY_SIZE ||
            issuerKey.empty() || issuerKey.size() != ED25519_PRIVATE_KEY_SIZE) {
            return std::nullopt;
        }

        time_t now = time(nullptr);

        // Special handling for self-signed root certificates
        bool isSelfSigned = (subject == issuerCert.subject && issuerCert.subject == issuerCert.issuer);

        if (!isSelfSigned) {
            // For non-root certificates, validate issuer certificate
            if (issuerCert.subject.empty() || issuerCert.issuer.empty() ||
                issuerCert.publicKey.empty()) {
                std::cerr << "Invalid issuer certificate format" << std::endl;
                return std::nullopt;
            }

            // Check issuer certificate validity unless in testing mode
            if (!testingMode_ && (now < issuerCert.notBefore || now > issuerCert.notAfter)) {
                std::cerr << "Issuer certificate expired or not yet valid" << std::endl;
                return std::nullopt;
            }

            // For non-root certs, signature is required
            if (!isSelfSigned && issuerCert.signature.empty()) {
                std::cerr << "Non-root certificate requires issuer signature" << std::endl;
                return std::nullopt;
            }
        }

        std::cerr << "Creating certificate for subject: " << subject 
                  << ", issuer: " << issuerCert.subject
                  << ", isSelfSigned: " << (isSelfSigned ? "true" : "false") << std::endl;

        // Calculate validity period
        int64_t validitySeconds;
        if (validityDays > 0) {
            validitySeconds = static_cast<int64_t>(validityDays) * 24 * 60 * 60;
            if (validitySeconds > std::numeric_limits<time_t>::max() - now) {
                validitySeconds = std::numeric_limits<time_t>::max() - now;
            }
        } else {
            // Default to issuer's remaining validity period
            validitySeconds = std::max<int64_t>(0, issuerCert.notAfter - now);
        }

        // Create new certificate
        Certificate cert;
        cert.publicKey = publicKey;
        cert.subject = subject;
        cert.issuer = issuerCert.subject;
        cert.notBefore = now;
        cert.notAfter = std::min(
            now + validitySeconds,
            issuerCert.notAfter);  // Can't exceed issuer's validity

        // Serialize and sign the certificate
        auto certData = serializeCertificate(cert);
        if (certData.empty()) {
            return std::nullopt;
        }

        cert.signature = sign(certData, issuerKey);
        if (cert.signature.empty()) {
            return std::nullopt;
        }

        // Verify the certificate can be validated
        if (!verify(certData, cert.signature, issuerCert.publicKey)) {
            return std::nullopt;
        }

        return cert;

    } catch (...) {
        return std::nullopt;
    }
}

bool SignatureSystem::verifyCertificateChain(
    const Certificate& cert,
    const std::vector<Certificate>& trustAnchors,
    const std::vector<Certificate>& intermediates) {

    try {
        if (trustAnchors.empty()) {
            return false;
        }

        // Check certificate format
        if (cert.subject.empty() || cert.issuer.empty() || 
            cert.publicKey.empty() || cert.signature.empty()) {
            return false;
        }

        time_t now = time(nullptr);
        
        const Certificate* current = &cert;
        std::set<std::string> visitedSubjects;  // Track visited certificates to prevent loops
        
        // Add initial certificate subject
        visitedSubjects.insert(cert.subject);

        for (;;) {
            // Verify current certificate's validity period unless in testing mode
            if (!testingMode_ && (now < current->notBefore || now > current->notAfter)) {
                std::cerr << "Certificate expired: " << current->subject << std::endl;
                return false;
            }

            // Find the issuer certificate in trust anchors or intermediates
            const Certificate* issuer = nullptr;
            auto checkIssuer = [&](const Certificate& candidate) {
                if (candidate.subject != current->issuer) {
                    return false;
                }
                
                // Verify issuer's validity period unless in testing mode
                if (!testingMode_ && (now < candidate.notBefore || now > candidate.notAfter)) {
                    std::cerr << "Issuer certificate expired: " << candidate.subject << std::endl;
                    return false;
                }

                // Check if this is a valid issuer
                auto certData = serializeCertificate(*current);
                if (certData.empty()) {
                    std::cerr << "Failed to serialize certificate: " << current->subject << std::endl;
                    return false;
                }
                
                if (!verify(certData, current->signature, candidate.publicKey)) {
                    std::cerr << "Invalid signature from issuer: " << candidate.subject << std::endl;
                    return false;
                }
                
                return true;
            };

            // Check if this is a matching trust anchor
            for (const auto& anchor : trustAnchors) {
                if (current->subject == anchor.subject && 
                    current->issuer == anchor.issuer &&
                    current->notBefore == anchor.notBefore &&
                    current->notAfter == anchor.notAfter &&
                    current->publicKey == anchor.publicKey) {

                    // For trust anchors, verify self-signature
                    auto certData = serializeCertificate(anchor);
                    if (certData.empty()) {
                        std::cerr << "Failed to serialize trust anchor: " << anchor.subject << std::endl;
                        return false;
                    }

                    if (verify(certData, anchor.signature, anchor.publicKey)) {
                        std::cerr << "Verified trust anchor: " << anchor.subject << std::endl;
                        return true;
                    }

                    std::cerr << "Invalid trust anchor signature: " << anchor.subject << std::endl;
                    return false;
                }
            }

            // First check trust anchors
            for (const auto& anchor : trustAnchors) {
                if (checkIssuer(anchor)) {
                    issuer = &anchor;
                    break;
                }
            }

            // Then check intermediates if no anchor found
            if (!issuer) {
                for (const auto& intermediate : intermediates) {
                    if (checkIssuer(intermediate)) {
                        issuer = &intermediate;
                        break;
                    }
                }
            }

            if (!issuer) {
                std::cerr << "No valid issuer found for: " << current->subject << std::endl;
                return false;
            } else {
                std::cerr << "Verified certificate: " << current->subject 
                         << " signed by " << issuer->subject << std::endl;

                // Move up the chain to the issuer
                if (!visitedSubjects.insert(issuer->subject).second) {
                    std::cerr << "Certificate chain loop detected at: " << issuer->subject << std::endl;
                    return false;
                }

                // Continue verification with issuer
                current = issuer;
            }
        }
    } catch (...) {
        return false;
    }
}

std::string SignatureSystem::exportCertificatePEM(
    const Certificate& cert) const {
    
    // Serialize certificate
    auto data = serializeCertificate(cert);
    data.insert(data.end(), cert.signature.begin(), cert.signature.end());

    // Convert to base64
    BIO* mem = BIO_new(BIO_s_mem());
    if (!mem) {
        return "";
    }
    std::unique_ptr<BIO, decltype(&BIO_free)> memGuard(mem, BIO_free);

    BIO* b64Bio = BIO_new(BIO_f_base64());
    if (!b64Bio) {
        return "";
    }
    std::unique_ptr<BIO, decltype(&BIO_free)> b64Guard(b64Bio, BIO_free);

    BIO_push(b64Bio, mem);
    BIO_write(b64Bio, data.data(), static_cast<int>(data.size()));
    BIO_flush(b64Bio);

    char buffer[BUFFER_SIZE];
    int readLen = BIO_read(mem, buffer, sizeof(buffer));
    if (readLen < 0) {
        return "";
    }

    std::stringstream ss;
    ss << "-----BEGIN CERTIFICATE-----\n"
       << std::string(buffer, static_cast<size_t>(readLen))
       << "-----END CERTIFICATE-----\n";

    return ss.str();
}

std::optional<SignatureSystem::Certificate> SignatureSystem::importCertificatePEM(
    const std::string& pem) const {
    
    // Find certificate boundaries
    auto begin = pem.find("-----BEGIN CERTIFICATE-----");
    auto end = pem.find("-----END CERTIFICATE-----");
    if (begin == std::string::npos || end == std::string::npos) {
        return std::nullopt;
    }

    begin += 27;  // Length of begin marker
    std::string b64 = pem.substr(begin, end - begin);

    // Decode base64
    BIO* mem = BIO_new_mem_buf(static_cast<const void*>(b64.c_str()),
                              static_cast<int>(b64.length()));
    if (!mem) {
        return std::nullopt;
    }
    std::unique_ptr<BIO, decltype(&BIO_free)> memGuard(mem, BIO_free);

    BIO* b64Bio = BIO_new(BIO_f_base64());
    if (!b64Bio) {
        return std::nullopt;
    }
    std::unique_ptr<BIO, decltype(&BIO_free)> b64Guard(b64Bio, BIO_free);

    BIO_push(b64Bio, mem);

    std::vector<uint8_t> data(BUFFER_SIZE);
    int readLen = BIO_read(b64Bio, data.data(), static_cast<int>(data.size()));
    if (readLen < 0) {
        return std::nullopt;
    }
    data.resize(static_cast<size_t>(readLen));

    // Extract signature
    if (data.size() < ED25519_SIGNATURE_SIZE) {
        return std::nullopt;
    }

    size_t sigOffset = data.size() - ED25519_SIGNATURE_SIZE;
    std::vector<uint8_t> certData;
    certData.reserve(sigOffset);
    certData.insert(certData.end(), data.begin(), data.begin() + static_cast<std::ptrdiff_t>(sigOffset));

    std::vector<uint8_t> signature;
    signature.reserve(ED25519_SIGNATURE_SIZE);
    signature.insert(signature.end(), 
                    data.begin() + static_cast<std::ptrdiff_t>(sigOffset), 
                    data.end());

    // Deserialize certificate
    auto cert = deserializeCertificate(certData);
    if (!cert) {
        return std::nullopt;
    }

    cert->signature = std::move(signature);
    return cert;
}

std::string SignatureSystem::exportPrivateKeyPEM(
    const SecureMemory::SecureVector<uint8_t>& privateKey,
    const std::string& password) const {

    // Create key
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr,
        privateKey.data(), privateKey.size());
    if (!pkey) {
        return "";
    }
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> keyGuard(pkey, EVP_PKEY_free);

    // Export to PEM
    BIO* mem = BIO_new(BIO_s_mem());
    if (!mem) {
        return "";
    }
    std::unique_ptr<BIO, decltype(&BIO_free)> memGuard(mem, BIO_free);

    if (!PEM_write_bio_PKCS8PrivateKey(
            mem, pkey,
            EVP_aes_256_cbc(),
            password.c_str(), static_cast<int>(password.length()),
            nullptr, nullptr)) {
        return "";
    }

    char buffer[BUFFER_SIZE];
    int readLen = BIO_read(mem, buffer, sizeof(buffer));
    if (readLen < 0) {
        return "";
    }

    return std::string(buffer, static_cast<size_t>(readLen));
}

std::optional<SecureMemory::SecureVector<uint8_t>>
SignatureSystem::importPrivateKeyPEM(
    const std::string& pem,
    const std::string& password) const {

    // Read PEM
    BIO* mem = BIO_new_mem_buf(static_cast<const void*>(pem.c_str()),
                              static_cast<int>(pem.length()));
    if (!mem) {
        return std::nullopt;
    }
    std::unique_ptr<BIO, decltype(&BIO_free)> memGuard(mem, BIO_free);

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(
        mem, nullptr, nullptr,
        const_cast<char*>(password.c_str()));
    if (!pkey) {
        return std::nullopt;
    }
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> keyGuard(pkey, EVP_PKEY_free);

    // Extract private key
    size_t keyLen = ED25519_PRIVATE_KEY_SIZE;
    SecureMemory::SecureVector<uint8_t> privateKey(keyLen);
    if (EVP_PKEY_get_raw_private_key(pkey, privateKey.data(), &keyLen) <= 0) {
        return std::nullopt;
    }

    return privateKey;
}

std::vector<uint8_t> SignatureSystem::serializeCertificate(
    const Certificate& cert) const {

    if (cert.subject.length() > MAX_STRING_LENGTH ||
        cert.issuer.length() > MAX_STRING_LENGTH) {
        return {};
    }

    std::vector<uint8_t> data;
    data.reserve(ED25519_PUBLIC_KEY_SIZE + cert.subject.length() + 
                cert.issuer.length() + 2 * sizeof(time_t) + 2);
    
    // Public key
    data.insert(data.end(),
                cert.publicKey.begin(),
                cert.publicKey.end());

    // Subject length and content
    data.push_back(static_cast<uint8_t>(cert.subject.length()));
    data.insert(data.end(),
                cert.subject.begin(),
                cert.subject.end());

    // Issuer length and content
    data.push_back(static_cast<uint8_t>(cert.issuer.length()));
    data.insert(data.end(),
                cert.issuer.begin(),
                cert.issuer.end());

    // Validity period
    const uint8_t* timePtr;
    timePtr = reinterpret_cast<const uint8_t*>(&cert.notBefore);
    data.insert(data.end(), timePtr, timePtr + sizeof(time_t));
    
    timePtr = reinterpret_cast<const uint8_t*>(&cert.notAfter);
    data.insert(data.end(), timePtr, timePtr + sizeof(time_t));

    return data;
}

std::optional<SignatureSystem::Certificate>
SignatureSystem::deserializeCertificate(
    const std::vector<uint8_t>& data) const {

    if (data.size() < ED25519_PUBLIC_KEY_SIZE + 2) {
        return std::nullopt;
    }

    Certificate cert;
    size_t pos = 0;

    // Public key
    cert.publicKey.assign(data.begin(), 
                         data.begin() + static_cast<std::ptrdiff_t>(ED25519_PUBLIC_KEY_SIZE));
    pos += ED25519_PUBLIC_KEY_SIZE;

    // Subject
    if (pos >= data.size()) return std::nullopt;
    uint8_t subjectLen = data[pos++];
    if (subjectLen > MAX_STRING_LENGTH || 
        pos + static_cast<size_t>(subjectLen) > data.size()) {
        return std::nullopt;
    }
    
    cert.subject = std::string(
        reinterpret_cast<const char*>(&data[pos]),
        static_cast<size_t>(subjectLen));
    pos += subjectLen;

    // Issuer
    if (pos >= data.size()) return std::nullopt;
    uint8_t issuerLen = data[pos++];
    if (issuerLen > MAX_STRING_LENGTH || 
        pos + static_cast<size_t>(issuerLen) > data.size()) {
        return std::nullopt;
    }
    
    cert.issuer = std::string(
        reinterpret_cast<const char*>(&data[pos]),
        static_cast<size_t>(issuerLen));
    pos += issuerLen;

    // Validity period
    if (pos + 2 * sizeof(time_t) > data.size()) {
        return std::nullopt;
    }
    std::memcpy(&cert.notBefore, &data[pos], sizeof(time_t));
    pos += sizeof(time_t);
    std::memcpy(&cert.notAfter, &data[pos], sizeof(time_t));

    return cert;
}

bool SignatureSystem::verifySignature(
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& signature,
    EVP_PKEY* key) const {

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        return false;
    }
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>
        ctxGuard(mdctx, EVP_MD_CTX_free);

    if (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, key) <= 0) {
        return false;
    }

    return EVP_DigestVerify(mdctx,
                           signature.data(), signature.size(),
                           data.data(), data.size()) == 1;
}

} // namespace encrypto::core
