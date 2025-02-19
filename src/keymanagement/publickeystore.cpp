#include "publickeystore.hpp"
#include <sqlite3.h>
#include <stdexcept>
#include <sstream>
#include <openssl/x509v3.h>

namespace encrypto {

class PublicKeyStore::Impl {
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
            CREATE TABLE IF NOT EXISTS user_keys (
                user_id TEXT PRIMARY KEY,
                certificate BLOB,
                created INTEGER,
                expires INTEGER,
                revoked BOOLEAN,
                revocation_reason TEXT
            );
            
            CREATE TABLE IF NOT EXISTS trust_relationships (
                truster_id TEXT,
                trustee_id TEXT,
                trust_level INTEGER CHECK(trust_level BETWEEN 0 AND 100),
                established INTEGER,
                revoked INTEGER,
                PRIMARY KEY (truster_id, trustee_id)
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

    bool addKey(const std::string& userId, X509* cert) {
        // Serialize certificate to DER format
        unsigned char* buf = nullptr;
        int len = i2d_X509(cert, &buf);
        if (len < 0) {
            return false;
        }

        std::string sql = "INSERT OR REPLACE INTO user_keys (user_id, certificate, created, expires, revoked) "
                         "VALUES (?, ?, ?, ?, 0)";
        
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            OPENSSL_free(buf);
            return false;
        }

        sqlite3_bind_text(stmt, 1, userId.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 2, buf, len, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 3, std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
        
        ASN1_TIME* expires = X509_get_notAfter(cert);
        int expiresDays = ASN1_TIME_diff(nullptr, nullptr, nullptr, expires);
        sqlite3_bind_int64(stmt, 4, std::chrono::system_clock::to_time_t(
            std::chrono::system_clock::now() + std::chrono::hours(24 * expiresDays)));

        bool success = sqlite3_step(stmt) == SQLITE_DONE;
        
        sqlite3_finalize(stmt);
        OPENSSL_free(buf);
        return success;
    }

    X509* getKey(const std::string& userId) const {
        std::string sql = "SELECT certificate FROM user_keys WHERE user_id = ? AND NOT revoked";
        
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            return nullptr;
        }

        sqlite3_bind_text(stmt, 1, userId.c_str(), -1, SQLITE_STATIC);
        
        X509* cert = nullptr;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* buf = static_cast<const unsigned char*>(sqlite3_column_blob(stmt, 0));
            int len = sqlite3_column_bytes(stmt, 0);
            const unsigned char* p = buf;
            cert = d2i_X509(nullptr, &p, len);
        }

        sqlite3_finalize(stmt);
        return cert;
    }

    bool revokeKey(const std::string& userId, const std::string& reason) {
        std::string sql = "UPDATE user_keys SET revoked = 1, revocation_reason = ? "
                         "WHERE user_id = ? AND NOT revoked";
        
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }

        sqlite3_bind_text(stmt, 1, reason.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, userId.c_str(), -1, SQLITE_STATIC);

        bool success = sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);
        return success;
    }

    bool establishTrust(const std::string& trusterId, const std::string& trusteeId, int level) {
        if (level < 0 || level > 100) {
            return false;
        }

        std::string sql = "INSERT OR REPLACE INTO trust_relationships "
                         "(truster_id, trustee_id, trust_level, established, revoked) "
                         "VALUES (?, ?, ?, ?, NULL)";
        
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }

        sqlite3_bind_text(stmt, 1, trusterId.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, trusteeId.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 3, level);
        sqlite3_bind_int64(stmt, 4, std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));

        bool success = sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);
        return success;
    }

    bool revokeTrust(const std::string& trusterId, const std::string& trusteeId) {
        std::string sql = "UPDATE trust_relationships SET revoked = ? "
                         "WHERE truster_id = ? AND trustee_id = ? AND revoked IS NULL";
        
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }

        sqlite3_bind_int64(stmt, 1, std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
        sqlite3_bind_text(stmt, 2, trusterId.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, trusteeId.c_str(), -1, SQLITE_STATIC);

        bool success = sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);
        return success;
    }

    int getTrustLevel(const std::string& trusterId, const std::string& trusteeId) const {
        std::string sql = "SELECT trust_level FROM trust_relationships "
                         "WHERE truster_id = ? AND trustee_id = ? AND revoked IS NULL";
        
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            return 0;
        }

        sqlite3_bind_text(stmt, 1, trusterId.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, trusteeId.c_str(), -1, SQLITE_STATIC);

        int level = 0;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            level = sqlite3_column_int(stmt, 0);
        }

        sqlite3_finalize(stmt);
        return level;
    }

    std::vector<TrustRelationship> getUserTrust(const std::string& userId) const {
        std::string sql = "SELECT * FROM trust_relationships "
                         "WHERE (truster_id = ? OR trustee_id = ?) AND revoked IS NULL";
        
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            return {};
        }

        sqlite3_bind_text(stmt, 1, userId.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, userId.c_str(), -1, SQLITE_STATIC);

        std::vector<TrustRelationship> relationships;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            TrustRelationship rel;
            rel.trusterId = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            rel.trusteeId = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            rel.trustLevel = sqlite3_column_int(stmt, 2);
            rel.established = std::chrono::system_clock::from_time_t(sqlite3_column_int64(stmt, 3));
            relationships.push_back(std::move(rel));
        }

        sqlite3_finalize(stmt);
        return relationships;
    }

private:
    sqlite3* db_;
};

// Main class implementation
PublicKeyStore::PublicKeyStore(const std::string& dbPath)
    : impl_(std::make_unique<Impl>(dbPath)) {
    if (!initializeDatabase()) {
        throw std::runtime_error("Failed to initialize database");
    }
}

PublicKeyStore::~PublicKeyStore() = default;

bool PublicKeyStore::addUserKey(const std::string& userId, X509* cert) {
    if (!validateCertificate(cert)) {
        return false;
    }
    return impl_->addKey(userId, cert);
}

X509* PublicKeyStore::getUserKey(const std::string& userId) const {
    return impl_->getKey(userId);
}

bool PublicKeyStore::revokeKey(const std::string& userId, const std::string& reason) {
    return impl_->revokeKey(userId, reason);
}

bool PublicKeyStore::establishTrust(const std::string& trusterId, 
                                  const std::string& trusteeId,
                                  int level) {
    return impl_->establishTrust(trusterId, trusteeId, level);
}

bool PublicKeyStore::revokeTrust(const std::string& trusterId,
                               const std::string& trusteeId) {
    return impl_->revokeTrust(trusterId, trusteeId);
}

int PublicKeyStore::getTrustLevel(const std::string& trusterId,
                                const std::string& trusteeId) const {
    return impl_->getTrustLevel(trusterId, trusteeId);
}

std::vector<PublicKeyStore::TrustRelationship> 
PublicKeyStore::getUserTrustRelationships(const std::string& userId) const {
    return impl_->getUserTrust(userId);
}

bool PublicKeyStore::initializeDatabase() {
    return impl_->initTables();
}

bool PublicKeyStore::validateCertificate(X509* cert) const {
    if (!cert) return false;

    // Basic validation
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (!pkey) return false;
    EVP_PKEY_free(pkey);

    // Check validity period
    if (X509_check_ca(cert) != 1) return false;
    
    return true;
}

bool PublicKeyStore::isKeyValid(const std::string& userId) const {
    X509* cert = getUserKey(userId);
    if (!cert) return false;

    bool valid = validateCertificate(cert);
    X509_free(cert);
    return valid;
}

void PublicKeyStore::cleanupExpiredKeys() {
    // TODO: Implement key cleanup
}

} // namespace encrypto
