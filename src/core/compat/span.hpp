#pragma once

#include <array>
#include <cstddef>
#include <type_traits>
#include <vector>

namespace encrypto::core::compat {

template<typename T>
class span {
public:
    using element_type = T;
    using value_type = std::remove_cv_t<T>;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;
    using iterator = pointer;
    using const_iterator = const_pointer;

    constexpr span() noexcept : data_(nullptr), size_(0) {}
    
    constexpr span(pointer ptr, size_type count) noexcept
        : data_(ptr), size_(count) {}

    template<std::size_t N>
    constexpr span(element_type (&arr)[N]) noexcept
        : data_(arr), size_(N) {}

    template<std::size_t N>
    constexpr span(std::array<value_type, N>& arr) noexcept
        : data_(arr.data()), size_(N) {}

    template<std::size_t N>
    constexpr span(const std::array<value_type, N>& arr) noexcept
        : data_(arr.data()), size_(N) {}

    // Constructor for std::vector
    constexpr span(std::vector<value_type>& vec) noexcept
        : data_(vec.data()), size_(vec.size()) {}

    constexpr span(const std::vector<value_type>& vec) noexcept
        : data_(const_cast<pointer>(vec.data())), size_(vec.size()) {}

    constexpr iterator begin() const noexcept { return data_; }
    constexpr iterator end() const noexcept { return data_ + size_; }
    constexpr const_iterator cbegin() const noexcept { return data_; }
    constexpr const_iterator cend() const noexcept { return data_ + size_; }

    constexpr reference operator[](size_type idx) const { return data_[idx]; }
    constexpr pointer data() const noexcept { return data_; }
    constexpr size_type size() const noexcept { return size_; }
    constexpr bool empty() const noexcept { return size_ == 0; }

private:
    pointer data_;
    size_type size_;
};

} // namespace encrypto::core::compat
