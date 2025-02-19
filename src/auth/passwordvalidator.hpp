#pragma once

#include "auth_export.hpp"
#include <string>
#include <string_view>
#include <optional>
#include <vector>

namespace encrypto::auth {

/**
 * @brief Password validation settings
 */
struct ENCRYPTO_AUTH_EXPORT PasswordRequirements {
    size_t min_length = 12;              // Minimum password length
    size_t max_length = 128;             // Maximum password length
    bool require_uppercase = true;        // Require at least one uppercase letter
    bool require_lowercase = true;        // Require at least one lowercase letter
    bool require_numbers = true;         // Require at least one number
    bool require_special = true;         // Require at least one special character
    bool disallow_repetition = true;     // Disallow character repetition >2
    bool disallow_common = true;         // Disallow common passwords
};

/**
 * @brief Password validation result
 */
struct ENCRYPTO_AUTH_EXPORT ValidationResult {
    bool valid;                     // Overall validation result
    std::vector<std::string> errors;  // List of validation errors if any
};

/**
 * @brief Password validation service
 *
 * Validates password strength and enforces security requirements
 */
class ENCRYPTO_AUTH_EXPORT PasswordValidator {
public:
    /**
     * @brief Constructor
     * @param requirements Password requirements to enforce
     */
    explicit PasswordValidator(PasswordRequirements requirements = {});

    /**
     * @brief Validate a password against requirements
     * @param password Password to validate
     * @return ValidationResult with status and any errors
     */
    ValidationResult validate(std::string_view password) const;

    /**
     * @brief Update password requirements
     * @param requirements New requirements to use
     */
    void setRequirements(PasswordRequirements requirements);

    /**
     * @brief Get current password requirements
     * @return Current requirements
     */
    const PasswordRequirements& getRequirements() const;

private:
    PasswordRequirements requirements_;
};

} // namespace encrypto::auth
