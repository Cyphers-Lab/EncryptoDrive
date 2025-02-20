#include "shareprotocol.hpp"
#include "sharemanager.hpp"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <random>
#include <sstream>
#include <iomanip>
#include <sqlite3.h>

namespace encrypto::keymanagement {

namespace {
    constexpr size_t KEY_SIZE = 32;
    constexpr size_t IV_SIZE = 16;
    constexpr char PACKAGE_MAGIC[] = "ENCRYPTOSHARE";
    constexpr int PACKAGE_VERSION = 1;
    
    // Default permissions for new shares
    const std::vector<std::string> DEFAULT_PERMISSIONS = {
        "read", "download", "list"
    };
}

class ShareProtocol::Impl {
public:
    Impl(const std::string& configPath) 
        : shareManager_(configPath), db_(nullptr) {
        if (sqlite3_open((configPath + "/shares.db").c_str(), &db_) != SQLITE_OK) {
            throw std::runtime_error("Failed to open share database");
        }
        initializeDatabase();
    }

    ~Impl() {
        if (db_) sqlite3_close(db_);
    }

    std::optional<ShareLink> createShare(
        const fs::path& path,
        const std::string& recipientId,
        std::chrono::seconds duration,
        bool offline) {
        
        // Generate unique share ID
        std::string shareId = generateShareId();
        
        // Create ephemeral key for this share
        auto ephemeralKey = shareManager_.generateEphemeralKey(
            "share:" + shareId,
            duration
        );
        if (!ephemeralKey) {
            return std::nullopt;
        }

        // Get recipient's public key
        auto recipientKey = getRecipientPublicKey(recipientId);
        if (!recipientKey) {
            return std::nullopt;
        }

        // Encrypt the file key for the recipient
        std::vector<uint8_t> encryptedKey;
        if (!encryptKeyForRecipient(*ephemeralKey, recipientKey->keyData, encryptedKey)) {
            return std::nullopt;
        }

        // Generate signature
        std::vector<uint8_t> signature = signShare(shareId, recipientId, encryptedKey);
        
        // Store share metadata
        if (!storeShareMetadata(shareId, path, recipientId, duration, offline)) {
            return std::nullopt;
        }

        // Grant permissions
        if (!shareManager_.grantAccess(recipientId, DEFAULT_PERMISSIONS, duration)) {
            return std::nullopt;
        }

        ShareLink link;
        link.id = shareId;
        link.recipientId = recipientId;
        link.encryptedKey = base64Encode(encryptedKey);
        link.signature = signature;
        link.expires = std::chrono::system_clock::now() + duration;
        link.offline = offline;

        return link;
    }

    bool verifyRecipient(const std::string& userId, const PublicKey& key) {
        // Verify key format and algorithm
        if (!isValidPublicKey(key)) {
            return false;
        }

        // Check key expiration
        if (key.expires && *key.expires < std::chrono::system_clock::now()) {
            return false;
        }

        // Verify against trusted directory
        return verifyKeyWithDirectory(userId, key);
    }

    bool revokeShare(const std::string& shareId) {
        // Get share metadata
        auto metadata = getShareInfo(shareId);
        if (!metadata) {
            return false;
        }

        // Revoke recipient's access
        if (!shareManager_.revokeAccess(metadata->recipientId)) {
            return false;
        }

        // Mark share as inactive
        const char* sql = "UPDATE shares SET active = 0 WHERE id = ?";
        sqlite3_stmt* stmt = nullptr;
        
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }

        sqlite3_bind_text(stmt, 1, shareId.c_str(), -1, SQLITE_STATIC);
        bool success = sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);

        return success;
    }

    std::optional<ShareMetadata> getShareInfo(const std::string& shareId) {
        const char* sql = R"(
            SELECT creator_id, recipient_id, resource_path, created, expires,
                   active, offline, permissions
            FROM shares WHERE id = ?
        )";

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return std::nullopt;
        }

        sqlite3_bind_text(stmt, 1, shareId.c_str(), -1, SQLITE_STATIC);
        
        ShareMetadata metadata;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            metadata.id = shareId;
            metadata.creatorId = reinterpret_cast<const char*>(
                sqlite3_column_text(stmt, 0));
            metadata.recipientId = reinterpret_cast<const char*>(
                sqlite3_column_text(stmt, 1));
            metadata.resourcePath = reinterpret_cast<const char*>(
                sqlite3_column_text(stmt, 2));
            metadata.created = std::chrono::system_clock::from_time_t(
                sqlite3_column_int64(stmt, 3));
            metadata.expires = std::chrono::system_clock::from_time_t(
                sqlite3_column_int64(stmt, 4));
            metadata.active = sqlite3_column_int(stmt, 5) != 0;
            metadata.offline = sqlite3_column_int(stmt, 6) != 0;
            
            // Parse permissions JSON
            auto permJson = nlohmann::json::parse(
                reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7)));
            metadata.permissions = permJson.get<std::vector<std::string>>();

            sqlite3_finalize(stmt);
            return metadata;
        }

        sqlite3_finalize(stmt);
        return std::nullopt;
    }

    bool acceptShare(const std::string& shareId, const PublicKey& recipientKey) {
        auto metadata = getShareInfo(shareId);
        if (!metadata || !metadata->active) {
            return false;
        }

        // Verify recipient's key
        if (!verifyRecipient(metadata->recipientId, recipientKey)) {
            return false;
        }

        // Verify share hasn't expired
        if (metadata->expires < std::chrono::system_clock::now()) {
            return false;
        }

        // Update share status
        const char* sql = "UPDATE shares SET accepted = 1 WHERE id = ?";
        sqlite3_stmt* stmt = nullptr;
        
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }

        sqlite3_bind_text(stmt, 1, shareId.c_str(), -1, SQLITE_STATIC);
        bool success = sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);

        return success;
    }

    std::vector<ShareMetadata> listShares() const {
        std::vector<ShareMetadata> shares;
        const char* sql = "SELECT * FROM shares WHERE active = 1";
        
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return shares;
        }

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            ShareMetadata metadata;
            metadata.id = reinterpret_cast<const char*>(
                sqlite3_column_text(stmt, 0));
            metadata.creatorId = reinterpret_cast<const char*>(
                sqlite3_column_text(stmt, 1));
            metadata.recipientId = reinterpret_cast<const char*>(
                sqlite3_column_text(stmt, 2));
            metadata.resourcePath = reinterpret_cast<const char*>(
                sqlite3_column_text(stmt, 3));
            metadata.created = std::chrono::system_clock::from_time_t(
                sqlite3_column_int64(stmt, 4));
            metadata.expires = std::chrono::system_clock::from_time_t(
                sqlite3_column_int64(stmt, 5));
            metadata.active = sqlite3_column_int(stmt, 6) != 0;
            metadata.offline = sqlite3_column_int(stmt, 7) != 0;

            auto permJson = nlohmann::json::parse(
                reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8)));
            metadata.permissions = permJson.get<std::vector<std::string>>();

            shares.push_back(std::move(metadata));
        }

        sqlite3_finalize(stmt);
        return shares;
    }

    std::optional<fs::path> createOfflinePackage(const std::string& shareId) {
        auto metadata = getShareInfo(shareId);
        if (!metadata || !metadata->offline) {
            return std::nullopt;
        }

        // Create package in temp directory
        fs::path packagePath = fs::temp_directory_path() / 
                             (shareId + ".encryptoshare");

        try {
            // Package structure
            nlohmann::json package;
            package["magic"] = PACKAGE_MAGIC;
            package["version"] = PACKAGE_VERSION;
            package["shareId"] = shareId;
            package["metadata"] = {
                {"creatorId", metadata->creatorId},
                {"recipientId", metadata->recipientId},
                {"resourcePath", metadata->resourcePath.string()},
                {"created", std::chrono::system_clock::to_time_t(metadata->created)},
                {"expires", std::chrono::system_clock::to_time_t(metadata->expires)},
                {"permissions", metadata->permissions}
            };

            // Get encrypted file key
            auto key = shareManager_.consumeEphemeralKey("share:" + shareId);
            if (key.empty()) {
                return std::nullopt;
            }
            package["encryptedKey"] = base64Encode(key);

            // Sign package
            auto signature = signPackage(package.dump());
            package["signature"] = base64Encode(signature);

            // Write package
            std::ofstream out(packagePath, std::ios::binary);
            out << package.dump(2);

            return packagePath;
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }

    std::optional<ShareMetadata> importOfflinePackage(
        const fs::path& packagePath,
        const PublicKey& recipientKey) {
        
        try {
            // Read and parse package
            std::ifstream in(packagePath, std::ios::binary);
            nlohmann::json package = nlohmann::json::parse(in);

            // Verify package format
            if (package["magic"] != PACKAGE_MAGIC ||
                package["version"] != PACKAGE_VERSION) {
                return std::nullopt;
            }

            // Verify signature
            auto signature = base64Decode(package["signature"].get<std::string>());
            auto content = package.dump();
            if (!verifyPackageSignature(content, signature)) {
                return std::nullopt;
            }

            // Verify recipient key
            std::string recipientId = package["metadata"]["recipientId"];
            if (!verifyRecipient(recipientId, recipientKey)) {
                return std::nullopt;
            }

            // Import metadata
            ShareMetadata metadata;
            metadata.id = package["shareId"];
            metadata.creatorId = package["metadata"]["creatorId"];
            metadata.recipientId = recipientId;
            metadata.resourcePath = package["metadata"]["resourcePath"].get<std::string>();
            metadata.created = std::chrono::system_clock::from_time_t(
                package["metadata"]["created"]);
            metadata.expires = std::chrono::system_clock::from_time_t(
                package["metadata"]["expires"]);
            metadata.active = true;
            metadata.offline = true;
            metadata.permissions = package["metadata"]["permissions"]
                .get<std::vector<std::string>>();

            // Store imported share
            if (!storeShareMetadata(metadata.id, metadata.resourcePath, 
                                  recipientId,
                                  metadata.expires - metadata.created,
                                  true)) {
                return std::nullopt;
            }

            // Store encrypted key
            auto key = base64Decode(package["encryptedKey"].get<std::string>());
            if (!storeImportedKey(metadata.id, key)) {
                return std::nullopt;
            }

            return metadata;
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }

private:
    ShareManager shareManager_;
    sqlite3* db_;

    void initializeDatabase() {
        const char* sql = R"(
            CREATE TABLE IF NOT EXISTS shares (
                id TEXT PRIMARY KEY,
                creator_id TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                resource_path TEXT NOT NULL,
                created INTEGER NOT NULL,
                expires INTEGER NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                offline INTEGER NOT NULL DEFAULT 0,
                accepted INTEGER NOT NULL DEFAULT 0,
                permissions TEXT NOT NULL,
                FOREIGN KEY(recipient_id) REFERENCES users(id)
            );
            
            CREATE INDEX IF NOT EXISTS idx_recipient 
            ON shares(recipient_id);
            
            CREATE INDEX IF NOT EXISTS idx_active 
            ON shares(active);
        )";

        char* errMsg = nullptr;
        if (sqlite3_exec(db_, sql, nullptr, nullptr, &errMsg) != SQLITE_OK) {
            std::string error = errMsg;
            sqlite3_free(errMsg);
            throw std::runtime_error("Failed to initialize database: " + error);
        }
    }

    std::string generateShareId() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> dis;
        
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < 4; ++i) {
            ss << std::setw(8) << dis(gen);
        }
        return ss.str();
    }

    bool storeShareMetadata(const std::string& shareId,
                          const fs::path& path,
                          const std::string& recipientId,
                          std::chrono::seconds duration,
                          bool offline) {
        const char* sql = R"(
            INSERT INTO shares (
                id, creator_id, recipient_id, resource_path, 
                created, expires, offline, permissions
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        )";

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }

        auto now = std::chrono::system_clock::now();
        nlohmann::json perms = DEFAULT_PERMISSIONS;

        sqlite3_bind_text(stmt, 1, shareId.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, "current_user", -1, SQLITE_STATIC); // TODO: Get actual user
        sqlite3_bind_text(stmt, 3, recipientId.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, path.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 5, std::chrono::system_clock::to_time_t(now));
        sqlite3_bind_int64(stmt, 6, std::chrono::system_clock::to_time_t(now + duration));
        sqlite3_bind_int(stmt, 7, offline ? 1 : 0);
        sqlite3_bind_text(stmt, 8, perms.dump().c_str(), -1, SQLITE_STATIC);

        bool success = sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);
        return success;
    }

    std::optional<PublicKey> getRecipientPublicKey(const std::string& userId) {
        // TODO: Implement key lookup from key server/directory
        return std::nullopt;
    }

    bool encryptKeyForRecipient(const std::vector<uint8_t>& key,
                               const std::vector<uint8_t>& recipientPubKey,
                               std::vector<uint8_t>& encryptedKey) {
        // TODO: Implement hybrid encryption (RSA + AES)
        return false;
    }

    std::vector<uint8_t> signShare(const std::string& shareId,
                                  const std::string& recipientId,
                                  const std::vector<uint8_t>& encryptedKey) {
        // TODO: Implement signature generation
        return std::vector<uint8_t>();
    }

    bool isValidPublicKey(const PublicKey& key) {
        // TODO: Implement key validation
        return false;
    }

    bool verifyKeyWithDirectory(const std::string& userId, 
                              const PublicKey& key) {
        // TODO: Implement directory verification
        return false;
    }

    std::vector<uint8_t> signPackage(const std::string& content) {
        // TODO: Implement package signing
        return std::vector<uint8_t>();
    }

    bool verifyPackageSignature(const std::string& content,
                               const std::vector<uint8_t>& signature) {
        // TODO: Implement signature verification
        return false;
    }

    bool storeImportedKey(const std::string& shareId,
                         const std::vector<uint8_t>& key) {
        // TODO: Implement key storage
        return false;
    }

    std::string base64Encode(const std::vector<uint8_t>& data) {
        // TODO: Implement base64 encoding
        return "";
    }

    std::vector<uint8_t> base64Decode(const std::string& encoded) {
        // TODO: Implement base64 decoding
        return std::vector<uint8_t>();
    }
};

// Public interface implementation
ShareProtocol::ShareProtocol(const std::string& configPath)
    : impl_(std::make_unique<Impl>(configPath)) {}

ShareProtocol::~ShareProtocol() = default;

std::optional<ShareLink> ShareProtocol::createShare(
    const fs::path& path,
    const std::string& recipientId,
    std::chrono::seconds duration,
    bool offline) {
    return impl_->createShare(path, recipientId, duration, offline);
}

bool ShareProtocol::verifyRecipient(
    const std::string& userId,
    const PublicKey& key) {
    return impl_->verifyRecipient(userId, key);
}

bool ShareProtocol::revokeShare(const std::string& shareId) {
    return impl_->revokeShare(shareId);
}

std::optional<ShareMetadata> ShareProtocol::getShareInfo(
    const std::string& shareId) {
    return impl_->getShareInfo(shareId);
}

bool ShareProtocol::acceptShare(
    const std::string& shareId,
    const PublicKey& recipientKey) {
    return impl_->acceptShare(shareId, recipientKey);
}

std::vector<ShareMetadata> ShareProtocol::listShares() const {
    return impl_->listShares();
}

std::optional<fs::path> ShareProtocol::createOfflinePackage(
    const std::string& shareId) {
    return impl_->createOfflinePackage(shareId);
}

std::optional<ShareMetadata> ShareProtocol::importOfflinePackage(
    const fs::path& packagePath,
    const PublicKey& recipientKey) {
    return impl_->importOfflinePackage(packagePath, recipientKey);
}

} // namespace encrypto::keymanagement
