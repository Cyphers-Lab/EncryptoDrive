#pragma once

#include "core/core_export.hpp"
#include <memory>
#include <vector>
#include <string>
#include <cstddef>

namespace encrypto::core {

/**
 * @brief Provides secure memory operations for sensitive data
 * 
 * Handles memory locking, secure allocation/deallocation,
 * and automatic memory wiping to protect sensitive data
 */
class ENCRYPTO_CORE_EXPORT SecureMemory {
public:
    /**
     * @brief Create a locked memory region
     * @param size Size in bytes to allocate
     * @return true if successfully allocated and locked
     */
    static bool allocate(size_t size);

    /**
     * @brief Release locked memory region
     */
    static void deallocate();

    /**
     * @brief Securely wipe memory region
     * @param ptr Pointer to memory
     * @param size Size in bytes
     */
    static void wipe(void* ptr, size_t size);

    /**
     * @brief Create secure buffer with auto-wiping
     * @param size Buffer size in bytes
     * @return Secure buffer or nullptr on failure
     */
    static std::unique_ptr<uint8_t[]> createBuffer(size_t size);

    /**
     * @brief Secure string class that auto-wipes memory
     */
    class SecureString {
    public:
        SecureString();
        explicit SecureString(const std::string& str);
        explicit SecureString(const char* str);
        ~SecureString();

        // Move operations
        SecureString(SecureString&& other) noexcept;
        SecureString& operator=(SecureString&& other) noexcept;

        // Prevent copying
        SecureString(const SecureString&) = delete;
        SecureString& operator=(const SecureString&) = delete;

        // Access
        const char* data() const { return data_.get(); }
        size_t size() const { return size_; }
        bool empty() const { return size_ == 0; }

        // Convert to std::string (use carefully!)
        std::string toString() const;

    private:
        std::unique_ptr<char[]> data_;
        size_t size_;
        void clear();
    };

    /**
     * @brief Secure vector class that auto-wipes memory
     */
    template<typename T>
    class SecureVector {
    public:
        SecureVector() : size_(0) {}
        explicit SecureVector(size_t size);

        // Iterator constructors
        template<typename InputIt>
        SecureVector(InputIt first, InputIt last)
            : data_(new T[std::distance(first, last)])
            , size_(std::distance(first, last)) {
            std::copy(first, last, data_.get());
        }
        ~SecureVector();

        // Move operations
        SecureVector(SecureVector&& other) noexcept;
        SecureVector& operator=(SecureVector&& other) noexcept;

        // Prevent copying
        SecureVector(const SecureVector&) = delete;
        SecureVector& operator=(const SecureVector&) = delete;

        // Access
        T* data() { return data_.get(); }
        const T* data() const { return data_.get(); }
        size_t size() const { return size_; }
        bool empty() const { return size_ == 0; }

        // Modify
        void resize(size_t new_size);
        void clear();

    private:
        std::unique_ptr<T[]> data_;
        size_t size_;
    };

private:
    static void* locked_memory_;
    static size_t locked_size_;
};

} // namespace encrypto::core
