#include "core/encryptionengine.hpp"
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <unordered_map>
#include <algorithm>
#include <string>
#include <vector>
#include <cstring>

namespace encrypto::core {

namespace {
// Common constants
constexpr size_t KEY_SIZE = 32;    // 256 bits
constexpr size_t TAG_SIZE = 16;    // 128 bits
constexpr size_t SALT_SIZE = 32;   // 256 bits for key derivation

// Algorithm-specific constants
constexpr size_t AES_GCM_IV_SIZE = 12;     // 96 bits
constexpr size_t CHACHA_IV_SIZE = 12;       // 96 bits
constexpr size_t XCHACHA_IV_SIZE = 24;      // 192 bits

// Algorithm name mapping
const std::unordered_map<Algorithm, const char*> ALGO_NAMES = {
    {Algorithm::AES_256_GCM, "AES-256-GCM"},
    {Algorithm::CHACHA20_POLY1305, "ChaCha20-Poly1305"},
    {Algorithm::XCHACHA20_POLY1305, "XChaCha20-Poly1305"}
};
} // namespace

EncryptionEngine::EncryptionEngine(Algorithm algo)
    : ctx_(EVP_CIPHER_CTX_new()), 
      currentAlgo_(algo),
      integrityVerifier_(std::make_unique<FileIntegrity>()) {
    if (!ctx_) {
        throw std::runtime_error("Failed to create cipher context");
    }
}

EncryptionEngine::~EncryptionEngine() {
    if (ctx_) {
        EVP_CIPHER_CTX_free(ctx_);
    }
}

void EncryptionEngine::setParams(const EncryptionParams& params) {
    params_ = params;
}

const EncryptionEngine::EncryptionParams& EncryptionEngine::getParams() const {
    return params_;
}

bool EncryptionEngine::setAlgorithm(Algorithm algo) {
    currentAlgo_ = algo;
    return initializeContext();
}

Algorithm EncryptionEngine::getAlgorithm() const {
    return currentAlgo_;
}

std::string EncryptionEngine::algorithmToString(Algorithm algo) {
    auto it = ALGO_NAMES.find(algo);
    return it != ALGO_NAMES.end() ? it->second : "Unknown";
}

const EVP_CIPHER* EncryptionEngine::getCipher() const {
    switch (currentAlgo_) {
        case Algorithm::AES_256_GCM:
            return EVP_aes_256_gcm();
        case Algorithm::CHACHA20_POLY1305:
            #if OPENSSL_VERSION_NUMBER >= 0x1010000fL
                return EVP_chacha20_poly1305();
            #else
                return nullptr;
            #endif
        case Algorithm::XCHACHA20_POLY1305:
            #if OPENSSL_VERSION_NUMBER >= 0x1010100fL
                return EVP_chacha20_poly1305(); // Fallback to regular ChaCha20
            #else
                return nullptr;
            #endif
        default:
            return nullptr;
    }
}

bool EncryptionEngine::initializeContext() {
    if (!ctx_) {
        ctx_ = EVP_CIPHER_CTX_new();
        if (!ctx_) return false;
    }
    return true;
}

SecureMemory::SecureVector<uint8_t> EncryptionEngine::appendIntegrityHash(
    const SecureMemory::SecureVector<uint8_t>& data) {
    // Calculate hash of data
    std::vector<uint8_t> temp(data.data(), data.data() + data.size());
    std::vector<uint8_t> hash = integrityVerifier_->calculateHash(temp);
    
    // Create secure output with hash appended
    SecureMemory::SecureVector<uint8_t> output(data.size() + hash.size());
    std::copy(data.data(), data.data() + data.size(), output.data());
    std::copy(hash.data(), hash.data() + hash.size(), 
             output.data() + data.size());
    
    // Securely wipe temporary buffers
    SecureMemory::wipe(temp.data(), temp.size());
    SecureMemory::wipe(hash.data(), hash.size());
    
    return output;
}

bool EncryptionEngine::verifyAndStripIntegrityHash(SecureMemory::SecureVector<uint8_t>& data) {
    const size_t hashSize = 32; // SHA-256
    
    if (data.size() < hashSize) {
        return false;
    }

    // Extract hash
    std::vector<uint8_t> expectedHash(hashSize);
    std::copy(data.data() + data.size() - hashSize, 
             data.data() + data.size(), expectedHash.data());
    
    // Create temporary buffer for verification
    std::vector<uint8_t> temp(data.data(), data.data() + data.size() - hashSize);
    
    // Verify integrity
    bool result = integrityVerifier_->verifyHash(temp, expectedHash);
    
    // Securely resize data removing hash
    if (result) {
        SecureMemory::SecureVector<uint8_t> newData(data.size() - hashSize);
        std::copy(data.data(), data.data() + data.size() - hashSize, 
                 newData.data());
        data = std::move(newData);
    }
    
    // Wipe temporary buffers
    SecureMemory::wipe(temp.data(), temp.size());
    SecureMemory::wipe(expectedHash.data(), expectedHash.size());
    
    return result;
}

SecureMemory::SecureVector<uint8_t> EncryptionEngine::encrypt(
    const SecureMemory::SecureVector<uint8_t>& key,
    const std::vector<uint8_t>& data,
    SecureMemory::SecureVector<uint8_t>& tag) {
    
    size_t iv_size;
    switch (currentAlgo_) {
        case Algorithm::AES_256_GCM: iv_size = AES_GCM_IV_SIZE; break;
        case Algorithm::CHACHA20_POLY1305: iv_size = CHACHA_IV_SIZE; break;
        case Algorithm::XCHACHA20_POLY1305: iv_size = XCHACHA_IV_SIZE; break;
        default: return SecureMemory::SecureVector<uint8_t>();
    }

    if (key.size() != KEY_SIZE || tag.size() != TAG_SIZE) {
        return SecureMemory::SecureVector<uint8_t>();
    }

    // Generate IV securely
    SecureMemory::SecureVector<uint8_t> iv(iv_size);
    if (!generateRandomBytes(compat::span<uint8_t>(iv.data(), iv_size))) {
        return SecureMemory::SecureVector<uint8_t>();
    }

    // Initialize encryption
    const EVP_CIPHER* cipher = getCipher();
    if (!cipher) return SecureMemory::SecureVector<uint8_t>();

    if (!EVP_EncryptInit_ex(ctx_, cipher, nullptr, key.data(), iv.data())) {
        return SecureMemory::SecureVector<uint8_t>();
    }

    // Allocate secure output buffer
    SecureMemory::SecureVector<uint8_t> output(data.size() + EVP_MAX_BLOCK_LENGTH);
    int out_len = 0;
    int total_len = 0;

    // Encrypt data
    if (!EVP_EncryptUpdate(ctx_, output.data(), &out_len,
                          data.data(), static_cast<int>(data.size()))) {
        return SecureMemory::SecureVector<uint8_t>();
    }
    total_len = out_len;

    // Finalize encryption
    if (!EVP_EncryptFinal_ex(ctx_, output.data() + total_len, &out_len)) {
        return SecureMemory::SecureVector<uint8_t>();
    }
    total_len += out_len;

    // Get authentication tag
    if (!EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data())) {
        return SecureMemory::SecureVector<uint8_t>();
    }

    // Create final output with IV
    SecureMemory::SecureVector<uint8_t> final_output(iv_size + static_cast<size_t>(total_len));
    std::copy(iv.data(), iv.data() + iv_size, final_output.data());
    std::copy(output.data(), output.data() + total_len, 
             final_output.data() + iv_size);

    return appendIntegrityHash(final_output);
}

std::vector<uint8_t> EncryptionEngine::decrypt(
    const SecureMemory::SecureVector<uint8_t>& key,
    const std::vector<uint8_t>& data,
    const SecureMemory::SecureVector<uint8_t>& tag) {
    
    size_t iv_size;
    switch (currentAlgo_) {
        case Algorithm::AES_256_GCM: iv_size = AES_GCM_IV_SIZE; break;
        case Algorithm::CHACHA20_POLY1305: iv_size = CHACHA_IV_SIZE; break;
        case Algorithm::XCHACHA20_POLY1305: iv_size = XCHACHA_IV_SIZE; break;
        default: return std::vector<uint8_t>();
    }

    if (data.size() < iv_size || key.size() != KEY_SIZE) {
        return std::vector<uint8_t>();
    }

    // Extract IV and create secure copy of encrypted data
    SecureMemory::SecureVector<uint8_t> secured_data(data.size());
    std::copy(data.begin(), data.end(), secured_data.data());
    
    std::vector<uint8_t> iv(data.begin(), data.begin() + static_cast<std::vector<uint8_t>::difference_type>(iv_size));
    std::vector<uint8_t> encrypted_data(data.begin() + static_cast<std::vector<uint8_t>::difference_type>(iv_size), data.end());
    secured_data = SecureMemory::SecureVector<uint8_t>(encrypted_data.size());
    std::copy(encrypted_data.begin(), encrypted_data.end(), secured_data.data());

    // Initialize decryption
    const EVP_CIPHER* cipher = getCipher();
    if (!cipher) return std::vector<uint8_t>();

    if (!EVP_DecryptInit_ex(ctx_, cipher, nullptr,
                           key.data(), iv.data())) {
        return std::vector<uint8_t>();
    }

    // Allocate output buffer
    SecureMemory::SecureVector<uint8_t> output(secured_data.size() + EVP_MAX_BLOCK_LENGTH);
    int out_len = 0;
    int total_len = 0;

    // Decrypt data
    if (!EVP_DecryptUpdate(ctx_, output.data(), &out_len,
                          secured_data.data(), static_cast<int>(secured_data.size()))) {
        return std::vector<uint8_t>();
    }
    total_len = out_len;

    // Set expected tag value
    if (!EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                            const_cast<uint8_t*>(tag.data()))) {
        return std::vector<uint8_t>();
    }

    // Finalize decryption and verify tag
    if (EVP_DecryptFinal_ex(ctx_, output.data() + total_len, &out_len) <= 0) {
        return std::vector<uint8_t>();
    }
    total_len += out_len;

    // Resize output to actual size
    SecureMemory::SecureVector<uint8_t> final_output(static_cast<size_t>(total_len));
    std::copy(output.data(), output.data() + total_len, final_output.data());

    // Verify and remove integrity hash
    if (!verifyAndStripIntegrityHash(final_output)) {
        return std::vector<uint8_t>();
    }

    // Convert to regular vector for return
    std::vector<uint8_t> result(final_output.data(),
                               final_output.data() + final_output.size());
    return result;
}

bool EncryptionEngine::generateRandomBytes(compat::span<uint8_t> output) {
    return RAND_bytes(output.data(), static_cast<int>(output.size())) == 1;
}

SecureMemory::SecureVector<uint8_t> EncryptionEngine::deriveKey(
    const SecureMemory::SecureString& password,
    const std::string& salt) const {
    
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, nullptr);
    if (!kctx) {
        return SecureMemory::SecureVector<uint8_t>();
    }

    if (EVP_PKEY_derive_init(kctx) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        return SecureMemory::SecureVector<uint8_t>();
    }

    // Set Scrypt parameters
    if (EVP_PKEY_CTX_set1_pbe_pass(kctx, password.data(), 
                                   static_cast<int>(password.size())) <= 0 ||
        EVP_PKEY_CTX_set1_scrypt_salt(kctx, 
            reinterpret_cast<const uint8_t*>(salt.data()),
            static_cast<int>(salt.size())) <= 0 ||
        EVP_PKEY_CTX_set_scrypt_N(kctx, params_.kdf_iterations) <= 0 ||
        EVP_PKEY_CTX_set_scrypt_r(kctx, params_.parallelism) <= 0 ||
        EVP_PKEY_CTX_set_scrypt_p(kctx, params_.parallelism) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        return SecureMemory::SecureVector<uint8_t>();
    }

    // Derive key
    SecureMemory::SecureVector<uint8_t> key(KEY_SIZE);
    size_t key_len = KEY_SIZE;
    
    if (EVP_PKEY_derive(kctx, key.data(), &key_len) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        return SecureMemory::SecureVector<uint8_t>();
    }

    EVP_PKEY_CTX_free(kctx);
    return key;
}

} // namespace encrypto::core
