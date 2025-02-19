#include "sharemanager.hpp"
#include <sqlite3.h>
#include <stdexcept>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>

namespace encrypto {

class ShareManager::Impl {
public:
    explicit Impl(const std::string& dbPath) : db_(nullptr) {
        if (sqlite3_open(dbPath.c_str(), &db_) != SQLITE_OK) {
            throw std::runtime_error("Failed to open database");
        }
    }

    ~Impl() {
        if (db_) {
            sqlite3_close(db_);
        }
    }

    bool initTables() {
        const char* sql = R"(
            CREATE TABLE IF NOT EXISTS access_controls (
                user_id TEXT,
                permission TEXT,
                granted_at INTEGER,
                expires_at INTEGER,
                revoked INTEGER,
                PRIMARY KEY (user_id, permission)
            );
            
            CREATE TABLE IF NOT EXISTS ephemeral_keys (
                key_id TEXT PRIMARY KEY,
                key_data BLOB,
                purpose TEXT,
                created_at INTEGER,
                expires_at INTEGER,
                consumed INTEGER DEFAULT 0
            );
        )";

        char* errMsg = nullptr;
        if (sqlite3_exec(db_, sql, nullptr, nullptr, &errMsg) != SQLITE_OK) {
            std::string error = errMsg;
            sqlite3_free(errMsg);
            return false;
        }
        return true;
    }

    bool grantAccess(const std::string& userId,
                    const std::vector<std::string>& permissions,
                    std::chrono::seconds duration) {
        const char* sql = "INSERT OR REPLACE INTO access_controls "
                         "(user_id, permission, granted_at, expires_at, revoked) "
                         "VALUES (?, ?, ?, ?, 0)";
        
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }

        auto now = std::chrono::system_clock::now();
        auto expiresAt = now + duration;
        
        bool success = true;
        for (const auto& perm : permissions) {
            sqlite3_bind_text(stmt, 1, userId.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, perm.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int64(stmt, 3, std::chrono::system_clock::to_time_t(now));
            sqlite3_bind_int64(stmt, 4, std::chrono::system_clock::to_time_t(expiresAt));

            if (sqlite3_step(stmt) != SQLITE_DONE) {
                success = false;
                break;
            }
            sqlite3_reset(stmt);
        }

        sqlite3_finalize(stmt);
        return success;
    }

    bool revokeAccess(const std::string& userId) {
        const char* sql = "UPDATE access_controls "
                         "SET revoked = ? WHERE user_id = ? AND revoked = 0";
        
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }

        sqlite3_bind_int64(stmt, 1, 
            std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
        sqlite3_bind_text(stmt, 2, userId.c_str(), -1, SQLITE_STATIC);

        bool success = sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);
        return success;
    }

    bool hasPermission(const std::string& userId, const std::string& permission) const {
        const char* sql = "SELECT 1 FROM access_controls "
                         "WHERE user_id = ? AND permission = ? "
                         "AND revoked = 0 AND expires_at > ?";
        
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }

        sqlite3_bind_text(stmt, 1, userId.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, permission.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 3, 
            std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));

        bool hasAccess = sqlite3_step(stmt) == SQLITE_ROW;
        sqlite3_finalize(stmt);
        return hasAccess;
    }

    std::optional<std::string> generateEphemeralKey(const std::string& purpose,
                                                   std::chrono::seconds lifetime) {
        std::vector<uint8_t> keyData(32); // 256-bit key
        if (RAND_bytes(keyData.data(), keyData.size()) != 1) {
            return std::nullopt;
        }

        // Generate key ID as SHA-256(purpose || timestamp || random_bytes)
        std::string timestampStr = std::to_string(
            std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
        
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, purpose.c_str(), purpose.length());
        SHA256_Update(&sha256, timestampStr.c_str(), timestampStr.length());
        SHA256_Update(&sha256, keyData.data(), keyData.size());
        SHA256_Final(hash, &sha256);

        // Convert hash to hex string for key ID
        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(hash[i]);
        }
        std::string keyId = ss.str();

        const char* sql = "INSERT INTO ephemeral_keys "
                         "(key_id, key_data, purpose, created_at, expires_at) "
                         "VALUES (?, ?, ?, ?, ?)";
        
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return std::nullopt;
        }

        auto now = std::chrono::system_clock::now();
        auto expiresAt = now + lifetime;

        sqlite3_bind_text(stmt, 1, keyId.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 2, keyData.data(), keyData.size(), SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, purpose.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 4, std::chrono::system_clock::to_time_t(now));
        sqlite3_bind_int64(stmt, 5, std::chrono::system_clock::to_time_t(expiresAt));

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            return std::nullopt;
        }

        sqlite3_finalize(stmt);
        return keyId;
    }

    std::vector<uint8_t> consumeEphemeralKey(const std::string& keyId) {
        const char* sql = "SELECT key_data FROM ephemeral_keys "
                         "WHERE key_id = ? AND consumed = 0 AND expires_at > ?";
        
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return {};
        }

        sqlite3_bind_text(stmt, 1, keyId.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 2, 
            std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));

        std::vector<uint8_t> keyData;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* data = sqlite3_column_blob(stmt, 0);
            int size = sqlite3_column_bytes(stmt, 0);
            keyData.assign(static_cast<const uint8_t*>(data),
                         static_cast<const uint8_t*>(data) + size);
        }
        sqlite3_finalize(stmt);

        if (!keyData.empty()) {
            // Mark key as consumed
            const char* updateSql = "UPDATE ephemeral_keys SET consumed = 1 "
                                  "WHERE key_id = ?";
            
            if (sqlite3_prepare_v2(db_, updateSql, -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, keyId.c_str(), -1, SQLITE_STATIC);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }

        return keyData;
    }

    std::vector<AccessControl> getUserAccess(const std::string& userId) const {
        const char* sql = "SELECT permission, expires_at FROM access_controls "
                         "WHERE user_id = ? AND revoked = 0 AND expires_at > ?";
        
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return {};
        }

        auto now = std::chrono::system_clock::now();
        sqlite3_bind_text(stmt, 1, userId.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 2, std::chrono::system_clock::to_time_t(now));

        std::vector<AccessControl> controls;
        AccessControl current;
        current.userId = userId;
        current.revoked = false;

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            current.permissions.push_back(
                reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
            current.expires = std::chrono::system_clock::from_time_t(
                sqlite3_column_int64(stmt, 1));
        }

        if (!current.permissions.empty()) {
            controls.push_back(std::move(current));
        }

        sqlite3_finalize(stmt);
        return controls;
    }

    std::vector<std::pair<std::string, EphemeralKey>> 
    getValidEphemeralKeys(const std::string& purpose) const {
        const char* sql = "SELECT key_id, key_data, created_at, expires_at "
                         "FROM ephemeral_keys "
                         "WHERE purpose = ? AND consumed = 0 AND expires_at > ?";
        
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return {};
        }

        auto now = std::chrono::system_clock::now();
        sqlite3_bind_text(stmt, 1, purpose.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 2, std::chrono::system_clock::to_time_t(now));

        std::vector<std::pair<std::string, EphemeralKey>> keys;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string keyId = reinterpret_cast<const char*>(
                sqlite3_column_text(stmt, 0));
            
            EphemeralKey key;
            const void* data = sqlite3_column_blob(stmt, 1);
            int size = sqlite3_column_bytes(stmt, 1);
            key.keyData.assign(static_cast<const uint8_t*>(data),
                             static_cast<const uint8_t*>(data) + size);
            key.created = std::chrono::system_clock::from_time_t(
                sqlite3_column_int64(stmt, 2));
            key.expires = std::chrono::system_clock::from_time_t(
                sqlite3_column_int64(stmt, 3));
            key.purpose = purpose;
            key.consumed = false;

            keys.emplace_back(keyId, std::move(key));
        }

        sqlite3_finalize(stmt);
        return keys;
    }

    void cleanup() {
        const char* sql = "DELETE FROM ephemeral_keys WHERE expires_at <= ?; "
                         "DELETE FROM access_controls WHERE expires_at <= ?;";

        auto now = std::chrono::system_clock::to_time_t(
            std::chrono::system_clock::now());

        char* errMsg = nullptr;
        sqlite3_exec(db_, sql, nullptr, nullptr, &errMsg);
        if (errMsg) {
            sqlite3_free(errMsg);
        }
    }

private:
    sqlite3* db_;
};

// Main class implementation
ShareManager::ShareManager(const std::string& dbPath)
    : impl_(std::make_unique<Impl>(dbPath)) {
    if (!initializeDatabase()) {
        throw std::runtime_error("Failed to initialize database");
    }
}

ShareManager::~ShareManager() = default;

bool ShareManager::grantAccess(const std::string& userId,
                             const std::vector<std::string>& permissions,
                             std::chrono::seconds duration) {
    return impl_->grantAccess(userId, permissions, duration);
}

bool ShareManager::revokeAccess(const std::string& userId) {
    return impl_->revokeAccess(userId);
}

bool ShareManager::hasPermission(const std::string& userId,
                               const std::string& permission) const {
    return impl_->hasPermission(userId, permission);
}

std::optional<std::string> ShareManager::generateEphemeralKey(
    const std::string& purpose,
    std::chrono::seconds lifetime) {
    return impl_->generateEphemeralKey(purpose, lifetime);
}

std::vector<uint8_t> ShareManager::consumeEphemeralKey(const std::string& keyId) {
    return impl_->consumeEphemeralKey(keyId);
}

std::vector<ShareManager::AccessControl> 
ShareManager::getUserAccess(const std::string& userId) const {
    return impl_->getUserAccess(userId);
}

std::vector<std::pair<std::string, ShareManager::EphemeralKey>>
ShareManager::getValidEphemeralKeys(const std::string& purpose) const {
    return impl_->getValidEphemeralKeys(purpose);
}

bool ShareManager::initializeDatabase() {
    return impl_->initTables();
}

void ShareManager::cleanupExpiredEntries() {
    impl_->cleanup();
}

std::vector<uint8_t> ShareManager::generateSecureRandomBytes(size_t length) const {
    std::vector<uint8_t> bytes(length);
    if (RAND_bytes(bytes.data(), length) != 1) {
        throw std::runtime_error("Failed to generate secure random bytes");
    }
    return bytes;
}

} // namespace encrypto
