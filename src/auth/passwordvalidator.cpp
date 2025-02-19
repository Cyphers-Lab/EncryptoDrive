#include "passwordvalidator.hpp"
#include <algorithm>
#include <array>
#include <regex>

namespace encrypto::auth {

namespace {
// Common weak passwords to disallow
const std::array<std::string_view, 20> common_passwords = {
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "letmein", "dragon", "111111", "baseball",
    "iloveyou", "trustno1", "sunshine", "master", "welcome",
    "shadow", "ashley", "football", "jesus", "michael"
};

// Special characters allowed in passwords
const std::string_view special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?";

bool hasRepeatingChars(std::string_view password) {
    if (password.length() < 3) return false;
    
    for (size_t i = 0; i < password.length() - 2; ++i) {
        if (password[i] == password[i+1] && 
            password[i] == password[i+2]) {
            return true;
        }
    }
    return false;
}

bool isCommonPassword(std::string_view password) {
    return std::find(common_passwords.begin(), 
                    common_passwords.end(),
                    password) != common_passwords.end();
}

bool containsUppercase(std::string_view password) {
    return std::any_of(password.begin(), password.end(), 
                      [](char c) { return std::isupper(c); });
}

bool containsLowercase(std::string_view password) {
    return std::any_of(password.begin(), password.end(),
                      [](char c) { return std::islower(c); });
}

bool containsNumber(std::string_view password) {
    return std::any_of(password.begin(), password.end(),
                      [](char c) { return std::isdigit(c); });
}

bool containsSpecial(std::string_view password) {
    return std::any_of(password.begin(), password.end(),
                      [](char c) { 
                          return special_chars.find(c) != std::string_view::npos;
                      });
}

} // namespace

PasswordValidator::PasswordValidator(PasswordRequirements requirements)
    : requirements_(std::move(requirements)) {
}

ValidationResult PasswordValidator::validate(std::string_view password) const {
    ValidationResult result;
    result.valid = true;
    
    // Check length requirements
    if (password.length() < requirements_.min_length) {
        result.valid = false;
        result.errors.push_back("Password is too short (minimum " + 
                               std::to_string(requirements_.min_length) + 
                               " characters)");
    }
    
    if (password.length() > requirements_.max_length) {
        result.valid = false;
        result.errors.push_back("Password is too long (maximum " + 
                               std::to_string(requirements_.max_length) + 
                               " characters)");
    }

    // Check character requirements
    if (requirements_.require_uppercase && !containsUppercase(password)) {
        result.valid = false;
        result.errors.push_back("Password must contain at least one uppercase letter");
    }
    
    if (requirements_.require_lowercase && !containsLowercase(password)) {
        result.valid = false;
        result.errors.push_back("Password must contain at least one lowercase letter");
    }
    
    if (requirements_.require_numbers && !containsNumber(password)) {
        result.valid = false;
        result.errors.push_back("Password must contain at least one number");
    }
    
    if (requirements_.require_special && !containsSpecial(password)) {
        result.valid = false;
        result.errors.push_back("Password must contain at least one special character");
    }

    // Check against common passwords
    if (requirements_.disallow_common && isCommonPassword(password)) {
        result.valid = false;
        result.errors.push_back("Password is too common");
    }

    // Check for character repetition
    if (requirements_.disallow_repetition && hasRepeatingChars(password)) {
        result.valid = false;
        result.errors.push_back(
            "Password cannot contain three or more repeating characters");
    }

    return result;
}

void PasswordValidator::setRequirements(PasswordRequirements requirements) {
    requirements_ = std::move(requirements);
}

const PasswordRequirements& PasswordValidator::getRequirements() const {
    return requirements_;
}

} // namespace encrypto::auth
