#include "keybackup.hpp"
#include <stdexcept>
#include <array>
#include <random>
#include <algorithm>

namespace encrypto {

// GF(256) multiplication table
static const std::array<std::array<uint8_t, 256>, 256> GF256_MUL = []() {
    std::array<std::array<uint8_t, 256>, 256> table{};
    for (int i = 0; i < 256; i++) {
        for (int j = 0; j < 256; j++) {
            uint16_t a = i, b = j, res = 0;
            for (int k = 0; k < 8; k++) {
                if (b & 1) res ^= a;
                a <<= 1;
                if (a & 0x100) a ^= 0x1B; // Reduction polynomial x^8 + x^4 + x^3 + x + 1
                b >>= 1;
            }
            table[i][j] = res;
        }
    }
    return table;
}();

KeyBackup::KeyBackup(uint8_t threshold, uint8_t total) 
    : threshold_(threshold), total_(total),
      ctx_(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr), EVP_PKEY_CTX_free) {
    
    if (threshold > total || total == 0 || total > 255) {
        throw std::invalid_argument("Invalid threshold or total shares");
    }
    
    if (!ctx_) {
        throw std::runtime_error("Failed to create crypto context");
    }
}

KeyBackup::~KeyBackup() = default;

std::vector<KeyBackup::Share> KeyBackup::splitKey(const std::vector<uint8_t>& key) {
    if (key.empty()) {
        throw std::invalid_argument("Empty key");
    }

    // Generate random coefficients for polynomial
    std::vector<std::vector<uint8_t>> coeffs(threshold_);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    // First coefficient is the secret
    coeffs[0] = key;
    
    // Generate random coefficients
    for (size_t i = 1; i < threshold_; i++) {
        coeffs[i].resize(key.size());
        for (size_t j = 0; j < key.size(); j++) {
            coeffs[i][j] = dis(gen);
        }
    }

    // Generate shares
    std::vector<Share> shares;
    shares.reserve(total_);
    
    for (uint8_t x = 1; x <= total_; x++) {
        Share share;
        share.index = x;
        share.data.resize(key.size());

        // Evaluate polynomial for each byte
        for (size_t i = 0; i < key.size(); i++) {
            uint8_t y = 0;
            for (size_t j = 0; j < threshold_; j++) {
                y = gf256_add(y, gf256_mul(coeffs[j][i], 
                    evaluatePolynomial(coeffs[j], x)));
            }
            share.data[i] = y;
        }
        shares.push_back(std::move(share));
    }

    return shares;
}

std::vector<uint8_t> KeyBackup::recoverKey(const std::vector<Share>& shares) {
    if (shares.size() < threshold_) {
        throw std::runtime_error("Not enough shares for recovery");
    }

    if (shares.empty() || shares[0].data.empty()) {
        throw std::invalid_argument("Invalid shares");
    }

    const size_t keySize = shares[0].data.size();
    std::vector<uint8_t> key(keySize);

    // Perform Lagrange interpolation for each byte
    for (size_t i = 0; i < keySize; i++) {
        std::vector<Share> byteShares;
        byteShares.reserve(shares.size());
        
        for (const auto& share : shares) {
            Share byteShare;
            byteShare.index = share.index;
            byteShare.data = {share.data[i]};
            byteShares.push_back(byteShare);
        }

        auto result = interpolatePolynomial(byteShares);
        key[i] = result[0];
    }

    return key;
}

KeyBackup::QRCode KeyBackup::shareToQR(const Share& share) {
    // TODO: Implement QR encoding using qrencode library
    KeyBackup::QRCode qr;
    qr.version = 1;
    qr.errorCorrection = 2; // Level Q (25%)
    
    // Format: version|EC|index|data
    std::string data;
    data.push_back(static_cast<char>(qr.version));
    data.push_back(static_cast<char>(qr.errorCorrection));
    data.push_back(static_cast<char>(share.index));
    
    for (uint8_t byte : share.data) {
        data.push_back(static_cast<char>(byte));
    }
    
    qr.data = std::move(data);
    return qr;
}

KeyBackup::Share KeyBackup::shareFromQR(const QRCode& qr) {
    if (qr.data.size() < 3) {
        throw std::runtime_error("Invalid QR code data");
    }

    KeyBackup::Share share;
    share.index = static_cast<uint8_t>(qr.data[2]);
    share.data.assign(qr.data.begin() + 3, qr.data.end());
    
    return share;
}

std::string KeyBackup::generatePaperBackup(const Share& share) {
    // TODO: Implement paper backup format with Reed-Solomon ECC
    std::string backup;
    // Format: Header|Index|Length|Data|Checksum
    backup = "ENCRYPTO_SHARE_V1\n";
    backup += std::to_string(share.index) + "\n";
    backup += std::to_string(share.data.size()) + "\n";
    
    // Encode data in base32 for paper backup
    static const char* BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    for (uint8_t byte : share.data) {
        backup += BASE32_CHARS[byte >> 3];
        backup += BASE32_CHARS[byte & 0x1F];
    }
    
    // Add simple checksum
    uint32_t checksum = 0;
    for (uint8_t byte : share.data) {
        checksum = (checksum << 8) | byte;
        checksum ^= checksum >> 16;
    }
    backup += "\n" + std::to_string(checksum);
    
    return backup;
}

KeyBackup::Share KeyBackup::recoverFromPaper(const std::string& backup) {
    // TODO: Implement paper backup recovery with error correction
    if (backup.substr(0, 17) != "ENCRYPTO_SHARE_V1\n") {
        throw std::runtime_error("Invalid paper backup format");
    }
    
    // Parse backup format
    size_t pos = 17;
    size_t nextPos = backup.find('\n', pos);
    if (nextPos == std::string::npos) {
        throw std::runtime_error("Invalid backup format");
    }
    
    KeyBackup::Share share;
    share.index = std::stoi(backup.substr(pos, nextPos - pos));
    
    pos = nextPos + 1;
    nextPos = backup.find('\n', pos);
    if (nextPos == std::string::npos) {
        throw std::runtime_error("Invalid backup format");
    }
    
    size_t dataLen = std::stoul(backup.substr(pos, nextPos - pos));
    share.data.reserve(dataLen);
    
    // TODO: Add proper base32 decoding with error correction
    
    return share;
}

bool KeyBackup::validateShares(const std::vector<Share>& shares) {
    if (shares.size() < threshold_) {
        return false;
    }

    try {
        // Attempt recovery and validate result
        recoverKey(shares);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

uint8_t KeyBackup::evaluatePolynomial(const std::vector<uint8_t>& coeffs, uint8_t x) {
    uint8_t result = coeffs[0];
    uint8_t power = 1;
    
    for (size_t i = 1; i < coeffs.size(); i++) {
        power = gf256_mul(power, x);
        result = gf256_add(result, gf256_mul(coeffs[i], power));
    }
    
    return result;
}

std::vector<uint8_t> KeyBackup::interpolatePolynomial(const std::vector<Share>& shares) {
    std::vector<uint8_t> result(shares[0].data.size(), 0);
    
    for (size_t i = 0; i < shares.size(); i++) {
        uint8_t li = 1;
        for (size_t j = 0; j < shares.size(); j++) {
            if (i != j) {
                li = gf256_mul(li, gf256_div(shares[j].index, 
                    gf256_add(shares[j].index, shares[i].index)));
            }
        }
        
        for (size_t k = 0; k < result.size(); k++) {
            result[k] = gf256_add(result[k], 
                gf256_mul(shares[i].data[k], li));
        }
    }
    
    return result;
}

uint8_t KeyBackup::gf256_add(uint8_t a, uint8_t b) {
    return a ^ b; // XOR for GF(256) addition
}

uint8_t KeyBackup::gf256_mul(uint8_t a, uint8_t b) {
    return GF256_MUL[a][b];
}

uint8_t KeyBackup::gf256_div(uint8_t a, uint8_t b) {
    if (b == 0) {
        throw std::runtime_error("Division by zero in GF(256)");
    }
    
    // Find multiplicative inverse using extended Euclidean algorithm
    uint8_t t = 0, newt = 1;
    uint8_t r = b, newr = a;
    
    while (newr != 0) {
        uint8_t quotient = r / newr;
        uint8_t tmp = t;
        t = newt;
        newt = tmp ^ gf256_mul(quotient, newt);
        tmp = r;
        r = newr;
        newr = tmp ^ gf256_mul(quotient, newr);
    }
    
    if (r > 1) {
        throw std::runtime_error("GF(256) division failed");
    }
    
    return t;
}

} // namespace encrypto
