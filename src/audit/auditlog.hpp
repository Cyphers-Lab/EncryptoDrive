#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <memory>
#include <optional>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <sqlite3.h>

namespace encrypto::audit {

enum class EventType {
    FILE_ACCESS,
    FILE_MODIFY,
    FILE_DELETE,
    SHARE_CREATE,
    SHARE_REVOKE,
    KEY_GENERATE,
    KEY_ROTATE,
    AUTH_SUCCESS,
    AUTH_FAILURE,
    CONFIG_CHANGE
};

struct EventData {
    std::string userId;
    std::string resourceId;
    std::string action;
    std::optional<std::string> details;
    std::chrono::system_clock::time_point timestamp;
};

struct Event {
    uint64_t id;
    EventType type;
    EventData data;
    std::vector<uint8_t> signature;
};

enum class Format {
    JSON,
    CSV,
    SYSLOG
};

struct TimeRange {
    std::chrono::system_clock::time_point start;
    std::chrono::system_clock::time_point end;
};

struct Query {
    std::optional<EventType> eventType;
    std::optional<std::string> userId;
    std::optional<std::string> resourceId;
    std::optional<TimeRange> timeRange;
};

struct ExportResult {
    bool success;
    std::string filePath;
    std::vector<uint8_t> signature;
    std::string error;
};

class AuditLog {
public:
    explicit AuditLog(const std::string& dbPath, const std::vector<uint8_t>& hmacKey);
    ~AuditLog();

    // Core logging functionality
    bool logEvent(EventType type, const EventData& data);
    bool verifyLogIntegrity(const TimeRange& range);
    ExportResult exportLogs(Format format, const TimeRange& range);
    std::vector<Event> queryLogs(const Query& filter);

    // Utility functions
    bool purgeOldLogs(std::chrono::system_clock::time_point before);
    bool rotateHmacKey(const std::vector<uint8_t>& newKey);
    std::optional<Event> getEventById(uint64_t eventId);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;

    // Prevent copying
    AuditLog(const AuditLog&) = delete;
    AuditLog& operator=(const AuditLog&) = delete;
};

} // namespace encrypto::audit
