#ifndef ENCRYPTO_KEYBACKUP_HPP
#define ENCRYPTO_KEYBACKUP_HPP

#include <vector>
#include <string>
#include <cstdint>
#include <memory>
#include <openssl/evp.h>

namespace encrypto {

/**
 * @brief Class handling key backup and recovery using Shamir's Secret Sharing
 */
class KeyBackup {
public:
    struct Share {
        uint8_t index;
        std::vector<uint8_t> data;
    };

    struct QRCode {
        std::string data;
        uint32_t version;
        uint8_t errorCorrection;
    };

    /**
     * @brief Create a new KeyBackup instance
     * @param threshold Minimum number of shares needed for recovery
     * @param total Total number of shares to generate
     * @throws std::invalid_argument if threshold > total or total > 255
     */
    KeyBackup(uint8_t threshold, uint8_t total);
    ~KeyBackup();

    /**
     * @brief Split a key into shares using Shamir's Secret Sharing
     * @param key Key to split
     * @return Vector of shares
     * @throws std::runtime_error on crypto operation failure
     */
    std::vector<Share> splitKey(const std::vector<uint8_t>& key);

    /**
     * @brief Recover key from shares
     * @param shares Vector of shares
     * @return Recovered key
     * @throws std::runtime_error if not enough valid shares
     */
    std::vector<uint8_t> recoverKey(const std::vector<Share>& shares);

    /**
     * @brief Generate QR code for a share
     * @param share Share to encode
     * @return QR code data
     */
    QRCode shareToQR(const Share& share);

    /**
     * @brief Parse share from QR code
     * @param qr QR code data
     * @return Parsed share
     * @throws std::runtime_error on invalid QR data
     */
    Share shareFromQR(const QRCode& qr);

    /**
     * @brief Generate paper backup format
     * @param share Share to format
     * @return Printable backup data with error correction
     */
    std::string generatePaperBackup(const Share& share);

    /**
     * @brief Recover share from paper backup
     * @param backup Paper backup data
     * @return Recovered share
     * @throws std::runtime_error on invalid backup data
     */
    Share recoverFromPaper(const std::string& backup);

    /**
     * @brief Validate a set of shares
     * @param shares Shares to validate
     * @return true if shares can recover the original key
     */
    bool validateShares(const std::vector<Share>& shares);

private:
    uint8_t threshold_;
    uint8_t total_;
    std::unique_ptr<EVP_PKEY_CTX, void(*)(EVP_PKEY_CTX*)> ctx_;

    // Polynomial evaluation in GF(256)
    uint8_t evaluatePolynomial(const std::vector<uint8_t>& coeffs, uint8_t x);
    
    // Lagrange interpolation in GF(256)
    std::vector<uint8_t> interpolatePolynomial(const std::vector<Share>& shares);

    // GF(256) arithmetic helpers
    uint8_t gf256_add(uint8_t a, uint8_t b);
    uint8_t gf256_mul(uint8_t a, uint8_t b);
    uint8_t gf256_div(uint8_t a, uint8_t b);
};

} // namespace encrypto

#endif // ENCRYPTO_KEYBACKUP_HPP
