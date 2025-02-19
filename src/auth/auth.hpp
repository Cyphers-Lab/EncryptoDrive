#pragma once

#include "auth_export.hpp"
#include "passwordvalidator.hpp"
#include <memory>
#include <string>
#include <chrono>
#include <optional>

namespace encrypto::auth {

/**
 * @brief Session information
 */
struct ENCRYPTO_AUTH_EXPORT SessionInfo {
    std::string user_id;
    std::chrono::system_clock::time_point created;
    std::chrono::system_clock::time_point expires;
    bool is_admin = false;
};

/**
 * @brief Authentication manager
 *
 * Handles user authentication, session management, and password validation
 */
class ENCRYPTO_AUTH_EXPORT AuthManager {
public:
    /**
     * @brief Constructor
     * @param password_validator Password validator to use
     */
    explicit AuthManager(std::shared_ptr<PasswordValidator> password_validator);

    /**
     * @brief Destructor
     */
    ~AuthManager();

    // Prevent copying
    AuthManager(const AuthManager&) = delete;
    AuthManager& operator=(const AuthManager&) = delete;

    /**
     * @brief Login with username and password
     * @param username Username
     * @param password Password
     * @return Optional session info if successful
     */
    std::optional<SessionInfo> login(std::string_view username, 
                                   std::string_view password);

    /**
     * @brief Check if a session is valid
     * @param session Session to validate
     * @return true if session is valid
     */
    bool validateSession(const SessionInfo& session) const;

    /**
     * @brief Change password for a user
     * @param username Username
     * @param old_password Old password
     * @param new_password New password
     * @return true if successful
     */
    bool changePassword(std::string_view username,
                       std::string_view old_password,
                       std::string_view new_password);

    /**
     * @brief Reset a user's password (admin only)
     * @param admin_session Admin session info
     * @param username Username to reset
     * @param new_password New password
     * @return true if successful
     */
    bool resetPassword(const SessionInfo& admin_session,
                      std::string_view username,
                      std::string_view new_password);

    /**
     * @brief Logout and invalidate session
     * @param session Session to invalidate
     */
    void logout(const SessionInfo& session);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace encrypto::auth
