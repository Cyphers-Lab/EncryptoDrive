#include "auth.hpp"
#include "../core/encryptionengine.hpp"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <mutex>
#include <unordered_map>
#include <chrono>
#include <random>
#include <algorithm>

namespace encrypto::auth {

namespace {
// Session duration (24 hours)
constexpr auto SESSION_DURATION = std::chrono::hours(24);

// Random session ID generation
std::string generateSessionId() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis;
    
    uint64_t random = dis(gen);
    return std::to_string(random);
}

// Password hashing using PBKDF2
std::vector<uint8_t> hashPassword(std::string_view password, 
                                const std::vector<uint8_t>& salt) {
    std::vector<uint8_t> hash(SHA512_DIGEST_LENGTH);
    
    PKCS5_PBKDF2_HMAC(password.data(), password.length(),
                      salt.data(), salt.size(),
                      10000, // Iterations
                      EVP_sha512(),
                      hash.size(),
                      hash.data());
    
    return hash;
}

} // namespace

// User account data
struct UserData {
    std::string username;
    std::vector<uint8_t> password_hash;
    std::vector<uint8_t> salt;
    bool is_admin;
};

class AuthManager::Impl {
public:
    explicit Impl(std::shared_ptr<PasswordValidator> password_validator)
        : password_validator_(std::move(password_validator)) {
        // Create default admin account
        createDefaultAdmin();
    }

    std::optional<SessionInfo> login(std::string_view username, 
                                   std::string_view password) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto user_it = users_.find(std::string(username));
        if (user_it == users_.end()) {
            return std::nullopt;
        }

        const auto& user = user_it->second;
        auto hash = hashPassword(password, user.salt);
        
        if (hash != user.password_hash) {
            return std::nullopt;
        }

        // Create new session
        SessionInfo session;
        session.user_id = std::string(username);
        session.created = std::chrono::system_clock::now();
        session.expires = session.created + SESSION_DURATION;
        session.is_admin = user.is_admin;

        const std::string session_id = generateSessionId();
        active_sessions_[session_id] = session;

        return session;
    }

    bool validateSession(const SessionInfo& session) const {
        std::lock_guard<std::mutex> lock(mutex_);

        // Check if session exists
        auto it = std::find_if(
            active_sessions_.begin(),
            active_sessions_.end(),
            [&session](const auto& pair) {
                return pair.second.user_id == session.user_id &&
                       pair.second.created == session.created;
            });

        if (it == active_sessions_.end()) {
            return false;
        }

        // Check if session has expired
        auto now = std::chrono::system_clock::now();
        return now < session.expires;
    }

    bool changePassword(std::string_view username,
                       std::string_view old_password,
                       std::string_view new_password) {
        std::lock_guard<std::mutex> lock(mutex_);

        // Validate credentials
        auto user_it = users_.find(std::string(username));
        if (user_it == users_.end()) {
            return false;
        }

        auto& user = user_it->second;
        auto old_hash = hashPassword(old_password, user.salt);
        if (old_hash != user.password_hash) {
            return false;
        }

        // Validate new password
        auto validation = password_validator_->validate(new_password);
        if (!validation.valid) {
            return false;
        }

        // Generate new salt and hash
        std::vector<uint8_t> new_salt(32);
        core::EncryptionEngine().generateRandomBytes(
            encrypto::core::compat::span<uint8_t>(new_salt));
        
        auto new_hash = hashPassword(new_password, new_salt);

        // Update password
        user.salt = std::move(new_salt);
        user.password_hash = std::move(new_hash);

        return true;
    }

    bool resetPassword(const SessionInfo& admin_session,
                      std::string_view username,
                      std::string_view new_password) {
        std::lock_guard<std::mutex> lock(mutex_);

        // Validate admin session
        if (!validateSession(admin_session) || !admin_session.is_admin) {
            return false;
        }

        // Find user
        auto user_it = users_.find(std::string(username));
        if (user_it == users_.end()) {
            return false;
        }

        // Validate new password
        auto validation = password_validator_->validate(new_password);
        if (!validation.valid) {
            return false;
        }

        // Generate new salt and hash
        auto& user = user_it->second;
        std::vector<uint8_t> new_salt(32);
        core::EncryptionEngine().generateRandomBytes(
            encrypto::core::compat::span<uint8_t>(new_salt));
        
        auto new_hash = hashPassword(new_password, new_salt);

        // Update password
        user.salt = std::move(new_salt);
        user.password_hash = std::move(new_hash);

        return true;
    }

    void logout(const SessionInfo& session) {
        std::lock_guard<std::mutex> lock(mutex_);

        // Remove matching session
        auto it = std::find_if(
            active_sessions_.begin(),
            active_sessions_.end(),
            [&session](const auto& pair) {
                return pair.second.user_id == session.user_id &&
                       pair.second.created == session.created;
            });

        if (it != active_sessions_.end()) {
            active_sessions_.erase(it);
        }
    }

private:
    void createDefaultAdmin() {
        const std::string default_admin = "admin";
        const std::string default_password = "changeme123!";

        // Generate salt
        std::vector<uint8_t> salt(32);
        core::EncryptionEngine().generateRandomBytes(
            encrypto::core::compat::span<uint8_t>(salt));

        // Create admin account
        UserData admin;
        admin.username = default_admin;
        admin.salt = std::move(salt);
        admin.password_hash = hashPassword(default_password, admin.salt);
        admin.is_admin = true;

        users_[default_admin] = std::move(admin);
    }

    std::shared_ptr<PasswordValidator> password_validator_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, UserData> users_;
    std::unordered_map<std::string, SessionInfo> active_sessions_;
};

// Public interface implementation
AuthManager::AuthManager(std::shared_ptr<PasswordValidator> password_validator)
    : impl_(std::make_unique<Impl>(std::move(password_validator))) {}

AuthManager::~AuthManager() = default;

std::optional<SessionInfo> AuthManager::login(std::string_view username, 
                                            std::string_view password) {
    return impl_->login(username, password);
}

bool AuthManager::validateSession(const SessionInfo& session) const {
    return impl_->validateSession(session);
}

bool AuthManager::changePassword(std::string_view username,
                               std::string_view old_password,
                               std::string_view new_password) {
    return impl_->changePassword(username, old_password, new_password);
}

bool AuthManager::resetPassword(const SessionInfo& admin_session,
                              std::string_view username,
                              std::string_view new_password) {
    return impl_->resetPassword(admin_session, username, new_password);
}

void AuthManager::logout(const SessionInfo& session) {
    impl_->logout(session);
}

} // namespace encrypto::auth
