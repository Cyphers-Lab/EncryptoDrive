#include "core/securememory.hpp"
#include <cstring>
#include <sys/mman.h>

namespace encrypto::core {

void* SecureMemory::locked_memory_ = nullptr;
size_t SecureMemory::locked_size_ = 0;

bool SecureMemory::allocate(size_t size) {
    if (locked_memory_) {
        return false;
    }

    locked_memory_ = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (locked_memory_ == MAP_FAILED) {
        locked_memory_ = nullptr;
        return false;
    }

    if (mlock(locked_memory_, size) != 0) {
        munmap(locked_memory_, size);
        locked_memory_ = nullptr;
        return false;
    }

    locked_size_ = size;
    return true;
}

void SecureMemory::deallocate() {
    if (locked_memory_) {
        munlock(locked_memory_, locked_size_);
        munmap(locked_memory_, locked_size_);
        locked_memory_ = nullptr;
        locked_size_ = 0;
    }
}

void SecureMemory::wipe(void* ptr, size_t size) {
    if (ptr && size > 0) {
        volatile unsigned char* p = static_cast<unsigned char*>(ptr);
        while (size--) {
            *p++ = 0;
        }
    }
}

std::unique_ptr<uint8_t[]> SecureMemory::createBuffer(size_t size) {
    auto buffer = std::make_unique<uint8_t[]>(size);
    if (buffer) {
        std::memset(buffer.get(), 0, size);
    }
    return buffer;
}

// SecureString implementation
SecureMemory::SecureString::SecureString() : size_(0) {}

SecureMemory::SecureString::SecureString(const std::string& str) 
    : data_(new char[str.length() + 1]), size_(str.length()) {
    std::memcpy(data_.get(), str.c_str(), size_ + 1);
}

SecureMemory::SecureString::SecureString(const char* str) 
    : data_(new char[strlen(str) + 1]), size_(strlen(str)) {
    std::memcpy(data_.get(), str, size_ + 1);
}

SecureMemory::SecureString::~SecureString() {
    clear();
}

SecureMemory::SecureString::SecureString(SecureString&& other) noexcept
    : data_(std::move(other.data_)), size_(other.size_) {
    other.size_ = 0;
}

SecureMemory::SecureString& SecureMemory::SecureString::operator=(SecureString&& other) noexcept {
    if (this != &other) {
        clear();
        data_ = std::move(other.data_);
        size_ = other.size_;
        other.size_ = 0;
    }
    return *this;
}

std::string SecureMemory::SecureString::toString() const {
    return data_ ? std::string(data_.get(), size_) : std::string();
}

void SecureMemory::SecureString::clear() {
    if (data_) {
        SecureMemory::wipe(data_.get(), size_ + 1);
    }
    data_.reset();
    size_ = 0;
}

// SecureVector implementation
template<typename T>
SecureMemory::SecureVector<T>::SecureVector(size_t size) 
    : data_(new T[size]), size_(size) {
    std::memset(data_.get(), 0, size * sizeof(T));
}

template<typename T>
SecureMemory::SecureVector<T>::~SecureVector() {
    clear();
}

template<typename T>
SecureMemory::SecureVector<T>::SecureVector(SecureVector&& other) noexcept
    : data_(std::move(other.data_)), size_(other.size_) {
    other.size_ = 0;
}

template<typename T>
SecureMemory::SecureVector<T>& SecureMemory::SecureVector<T>::operator=(SecureVector&& other) noexcept {
    if (this != &other) {
        clear();
        data_ = std::move(other.data_);
        size_ = other.size_;
        other.size_ = 0;
    }
    return *this;
}

template<typename T>
void SecureMemory::SecureVector<T>::resize(size_t new_size) {
    if (new_size == size_) return;
    
    auto new_data = std::make_unique<T[]>(new_size);
    if (data_) {
        std::memcpy(new_data.get(), data_.get(), 
                   std::min(size_, new_size) * sizeof(T));
        clear();
    }
    data_ = std::move(new_data);
    size_ = new_size;
}

template<typename T>
void SecureMemory::SecureVector<T>::clear() {
    if (data_) {
        SecureMemory::wipe(data_.get(), size_ * sizeof(T));
    }
    data_.reset();
    size_ = 0;
}

// Explicit template instantiations for common types
template class SecureMemory::SecureVector<uint8_t>;
template class SecureMemory::SecureVector<char>;

} // namespace encrypto::core
