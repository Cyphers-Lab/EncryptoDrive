#include "core/fileintegrity.hpp"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <fstream>

namespace encrypto::core {

class FileIntegrity::Impl {
public:
    explicit Impl(HashAlgorithm algo) : ctx_(EVP_MD_CTX_new()) {
        setAlgorithm(algo);
    }

    ~Impl() {
        if (ctx_) {
            EVP_MD_CTX_free(ctx_);
        }
    }

    void setAlgorithm(HashAlgorithm algo) {
        algorithm_ = algo;
        switch (algo) {
            case HashAlgorithm::SHA256:
                md_ = EVP_sha256();
                break;
            case HashAlgorithm::BLAKE2b:
                md_ = EVP_blake2b512();
                break;
        }
    }

    std::vector<uint8_t> calculateHash(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> hash(EVP_MAX_MD_SIZE);
        unsigned int hashLen;

        if (!EVP_DigestInit_ex(ctx_, md_, nullptr) ||
            !EVP_DigestUpdate(ctx_, data.data(), data.size()) ||
            !EVP_DigestFinal_ex(ctx_, hash.data(), &hashLen)) {
            return {};
        }

        hash.resize(hashLen);
        return hash;
    }

    std::vector<uint8_t> calculateFileHash(const std::string& filepath) {
        std::ifstream file(filepath, std::ios::binary);
        if (!file) {
            return {};
        }

        if (!EVP_DigestInit_ex(ctx_, md_, nullptr)) {
            return {};
        }

        char buffer[4096];
        while (file.read(buffer, sizeof(buffer))) {
            if (!EVP_DigestUpdate(ctx_, buffer, static_cast<size_t>(file.gcount()))) {
                return {};
            }
        }

        if (file.gcount() > 0) {
            if (!EVP_DigestUpdate(ctx_, buffer, static_cast<size_t>(file.gcount()))) {
                return {};
            }
        }

        std::vector<uint8_t> hash(EVP_MAX_MD_SIZE);
        unsigned int hashLen;
        if (!EVP_DigestFinal_ex(ctx_, hash.data(), &hashLen)) {
            return {};
        }

        hash.resize(hashLen);
        return hash;
    }

    bool verifyHash(const std::vector<uint8_t>& data,
                   const std::vector<uint8_t>& hash) {
        auto calculated = calculateHash(data);
        return !calculated.empty() && calculated == hash;
    }

    bool verifyFileHash(const std::string& filepath,
                       const std::vector<uint8_t>& hash) {
        auto calculated = calculateFileHash(filepath);
        return !calculated.empty() && calculated == hash;
    }

    size_t getHashSize() const {
        return static_cast<size_t>(EVP_MD_size(md_));
    }

private:
    EVP_MD_CTX* ctx_;
    const EVP_MD* md_;
    HashAlgorithm algorithm_;
};

FileIntegrity::FileIntegrity(HashAlgorithm algo)
    : impl_(std::make_unique<Impl>(algo)), algorithm_(algo) {}

FileIntegrity::~FileIntegrity() = default;

std::vector<uint8_t> FileIntegrity::calculateHash(
    const std::vector<uint8_t>& data) {
    return impl_->calculateHash(data);
}

std::vector<uint8_t> FileIntegrity::calculateFileHash(
    const std::string& filepath) {
    return impl_->calculateFileHash(filepath);
}

bool FileIntegrity::verifyHash(const std::vector<uint8_t>& data,
                             const std::vector<uint8_t>& hash) {
    return impl_->verifyHash(data, hash);
}

bool FileIntegrity::verifyFileHash(const std::string& filepath,
                                 const std::vector<uint8_t>& hash) {
    return impl_->verifyFileHash(filepath, hash);
}

void FileIntegrity::setAlgorithm(HashAlgorithm algo) {
    impl_->setAlgorithm(algo);
    algorithm_ = algo;
}

size_t FileIntegrity::getHashSize() const {
    return impl_->getHashSize();
}

} // namespace encrypto::core
