#include "auditlog.hpp"
#include <array>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <stdexcept>
#include <nlohmann/json.hpp>

namespace encrypto::audit {

// Schema version for database migrations
constexpr int SCHEMA_VERSION = 1;

// SQL statements
namespace sql {
    const char* CREATE_TABLES = R"(
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type INTEGER NOT NULL,
            user_id TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            timestamp INTEGER NOT NULL,
            signature BLOB NOT NULL
        );
        
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY
        );
        
        CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_user ON audit_log(user_id);
        CREATE INDEX IF NOT EXISTS idx_resource ON audit_log(resource_id);
    )";

    const char* INSERT_EVENT = R"(
        INSERT INTO audit_log (
            event_type, user_id, resource_id, action, details, timestamp, signature
        ) VALUES (?, ?, ?, ?, ?, ?, ?);
    )";

    const char* QUERY_EVENTS = R"(
        SELECT * FROM audit_log WHERE 1=1
    )";
}

class AuditLog::Impl {
public:
    Impl(const std::string& dbPath, const std::vector<uint8_t>& key) 
        : hmacKey_(key) {
        if (sqlite3_open(dbPath.c_str(), &db_) != SQLITE_OK) {
            throw std::runtime_error("Failed to open audit log database");
        }
        initializeDatabase();
    }

    ~Impl() {
        if (db_) sqlite3_close(db_);
    }

    bool logEvent(EventType type, const EventData& data) {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql::INSERT_EVENT, -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }

        // Generate HMAC signature
        auto signature = generateSignature(type, data);
        
        // Bind parameters
        sqlite3_bind_int(stmt, 1, static_cast<int>(type));
        sqlite3_bind_text(stmt, 2, data.userId.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, data.resourceId.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, data.action.c_str(), -1, SQLITE_STATIC);
        if (data.details) {
            sqlite3_bind_text(stmt, 5, data.details->c_str(), -1, SQLITE_STATIC);
        } else {
            sqlite3_bind_null(stmt, 5);
        }
        sqlite3_bind_int64(stmt, 6, std::chrono::system_clock::to_time_t(data.timestamp));
        sqlite3_bind_blob(stmt, 7, signature.data(), signature.size(), SQLITE_STATIC);

        bool success = sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);
        return success;
    }

    bool verifyLogIntegrity(const TimeRange& range) {
        std::stringstream query;
        query << sql::QUERY_EVENTS 
              << " AND timestamp >= ? AND timestamp <= ? ORDER BY id";

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, query.str().c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }

        sqlite3_bind_int64(stmt, 1, std::chrono::system_clock::to_time_t(range.start));
        sqlite3_bind_int64(stmt, 2, std::chrono::system_clock::to_time_t(range.end));

        bool valid = true;
        while (sqlite3_step(stmt) == SQLITE_ROW && valid) {
            EventType type = static_cast<EventType>(sqlite3_column_int(stmt, 1));
            EventData data{
                reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2)),  // userId
                reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3)),  // resourceId
                reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4)),  // action
                std::nullopt,  // details
                std::chrono::system_clock::from_time_t(sqlite3_column_int64(stmt, 6))
            };
            
            if (sqlite3_column_type(stmt, 5) != SQLITE_NULL) {
                data.details = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
            }

            auto storedSig = std::vector<uint8_t>(
                static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 7)),
                static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 7)) + sqlite3_column_bytes(stmt, 7)
            );

            auto computedSig = generateSignature(type, data);
            if (storedSig != computedSig) {
                valid = false;
                break;
            }
        }

        sqlite3_finalize(stmt);
        return valid;
    }

    ExportResult exportLogs(Format format, const TimeRange& range) {
        ExportResult result;
        std::vector<Event> events = queryLogs({
            std::nullopt, std::nullopt, std::nullopt, range
        });

        if (events.empty()) {
            result.success = true;
            result.error = "No events found in specified range";
            return result;
        }

        std::stringstream output;
        switch (format) {
            case Format::JSON: {
                nlohmann::json j = nlohmann::json::array();
                for (const auto& event : events) {
                    nlohmann::json event_json;
                    event_json["id"] = event.id;
                    event_json["type"] = static_cast<int>(event.type);
                    event_json["userId"] = event.data.userId;
                    event_json["resourceId"] = event.data.resourceId;
                    event_json["action"] = event.data.action;
                    event_json["details"] = event.data.details.value_or("");
                    event_json["timestamp"] = std::chrono::system_clock::to_time_t(event.data.timestamp);
                    j.push_back(event_json);
                }
                output << j.dump(2);
                break;
            }
            case Format::CSV: {
                output << "ID,Type,UserID,ResourceID,Action,Details,Timestamp\n";
                for (const auto& event : events) {
                    output << event.id << ","
                          << static_cast<int>(event.type) << ","
                          << event.data.userId << ","
                          << event.data.resourceId << ","
                          << event.data.action << ","
                          << (event.data.details ? *event.data.details : "") << ","
                          << std::chrono::system_clock::to_time_t(event.data.timestamp)
                          << "\n";
                }
                break;
            }
            case Format::SYSLOG: {
                for (const auto& event : events) {
                    output << "<audit>" 
                          << std::chrono::system_clock::to_time_t(event.data.timestamp)
                          << " user=" << event.data.userId
                          << " resource=" << event.data.resourceId
                          << " action=" << event.data.action;
                    if (event.data.details) {
                        output << " details=" << *event.data.details;
                    }
                    output << "\n";
                }
                break;
            }
        }

        // Generate signature for exported content
        std::vector<uint8_t> signature = generateSignature(
            reinterpret_cast<const uint8_t*>(output.str().data()),
            output.str().size()
        );

        result.success = true;
        result.signature = signature;
        // In a real implementation, we would write to a file and set result.filePath
        return result;
    }

    std::vector<Event> queryLogs(const Query& filter) {
        std::stringstream query;
        query << sql::QUERY_EVENTS;
        std::vector<std::string> conditions;

        if (filter.eventType) {
            conditions.push_back("event_type = " + 
                std::to_string(static_cast<int>(*filter.eventType)));
        }
        if (filter.userId) {
            conditions.push_back("user_id = '" + *filter.userId + "'");
        }
        if (filter.resourceId) {
            conditions.push_back("resource_id = '" + *filter.resourceId + "'");
        }
        if (filter.timeRange) {
            conditions.push_back("timestamp >= " + 
                std::to_string(std::chrono::system_clock::to_time_t(
                    filter.timeRange->start)));
            conditions.push_back("timestamp <= " + 
                std::to_string(std::chrono::system_clock::to_time_t(
                    filter.timeRange->end)));
        }

        for (size_t i = 0; i < conditions.size(); ++i) {
            query << " AND " << conditions[i];
        }
        query << " ORDER BY timestamp DESC";

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, query.str().c_str(), -1, &stmt, nullptr) 
            != SQLITE_OK) {
            return {};
        }

        std::vector<Event> events;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            Event event;
            event.id = sqlite3_column_int64(stmt, 0);
            event.type = static_cast<EventType>(sqlite3_column_int(stmt, 1));
            event.data.userId = reinterpret_cast<const char*>(
                sqlite3_column_text(stmt, 2));
            event.data.resourceId = reinterpret_cast<const char*>(
                sqlite3_column_text(stmt, 3));
            event.data.action = reinterpret_cast<const char*>(
                sqlite3_column_text(stmt, 4));
            
            if (sqlite3_column_type(stmt, 5) != SQLITE_NULL) {
                event.data.details = reinterpret_cast<const char*>(
                    sqlite3_column_text(stmt, 5));
            }
            
            event.data.timestamp = std::chrono::system_clock::from_time_t(
                sqlite3_column_int64(stmt, 6));
            
            auto sigSize = sqlite3_column_bytes(stmt, 7);
            event.signature.resize(sigSize);
            std::memcpy(event.signature.data(), 
                       sqlite3_column_blob(stmt, 7), 
                       sigSize);
            
            events.push_back(std::move(event));
        }

        sqlite3_finalize(stmt);
        return events;
    }

private:
    sqlite3* db_ = nullptr;
    std::vector<uint8_t> hmacKey_;

    void initializeDatabase() {
        char* errMsg = nullptr;
        if (sqlite3_exec(db_, sql::CREATE_TABLES, nullptr, nullptr, &errMsg) 
            != SQLITE_OK) {
            std::string error = errMsg;
            sqlite3_free(errMsg);
            throw std::runtime_error("Failed to initialize database: " + error);
        }
    }

    std::vector<uint8_t> generateSignature(EventType type, const EventData& data) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return {};

        EVP_PKEY* pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr,
            hmacKey_.data(), hmacKey_.size());
        if (!pkey) {
            EVP_MD_CTX_free(ctx);
            return {};
        }

        if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) != 1) {
            EVP_PKEY_free(pkey);
            EVP_MD_CTX_free(ctx);
            return {};
        }

        // Include all fields in signature
        EVP_DigestSignUpdate(ctx, &type, sizeof(type));
        EVP_DigestSignUpdate(ctx, data.userId.c_str(), data.userId.size());
        EVP_DigestSignUpdate(ctx, data.resourceId.c_str(), data.resourceId.size());
        EVP_DigestSignUpdate(ctx, data.action.c_str(), data.action.size());
        if (data.details) {
            EVP_DigestSignUpdate(ctx, data.details->c_str(), data.details->size());
        }
        auto timestamp = std::chrono::system_clock::to_time_t(data.timestamp);
        EVP_DigestSignUpdate(ctx, &timestamp, sizeof(timestamp));

        size_t sigLen;
        EVP_DigestSignFinal(ctx, nullptr, &sigLen);
        std::vector<uint8_t> signature(sigLen);
        EVP_DigestSignFinal(ctx, signature.data(), &sigLen);

        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(ctx);
        return signature;
    }

    std::vector<uint8_t> generateSignature(const uint8_t* data, size_t len) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return {};

        EVP_PKEY* pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr,
            hmacKey_.data(), hmacKey_.size());
        if (!pkey) {
            EVP_MD_CTX_free(ctx);
            return {};
        }

        if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) != 1) {
            EVP_PKEY_free(pkey);
            EVP_MD_CTX_free(ctx);
            return {};
        }

        EVP_DigestSignUpdate(ctx, data, len);

        size_t sigLen;
        EVP_DigestSignFinal(ctx, nullptr, &sigLen);
        std::vector<uint8_t> signature(sigLen);
        EVP_DigestSignFinal(ctx, signature.data(), &sigLen);

        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(ctx);
        return signature;
    }
};

// Public interface implementation
AuditLog::AuditLog(const std::string& dbPath, const std::vector<uint8_t>& hmacKey)
    : impl_(std::make_unique<Impl>(dbPath, hmacKey)) {}

AuditLog::~AuditLog() = default;

bool AuditLog::logEvent(EventType type, const EventData& data) {
    return impl_->logEvent(type, data);
}

bool AuditLog::verifyLogIntegrity(const TimeRange& range) {
    return impl_->verifyLogIntegrity(range);
}

ExportResult AuditLog::exportLogs(Format format, const TimeRange& range) {
    return impl_->exportLogs(format, range);
}

std::vector<Event> AuditLog::queryLogs(const Query& filter) {
    return impl_->queryLogs(filter);
}

} // namespace encrypto::audit
