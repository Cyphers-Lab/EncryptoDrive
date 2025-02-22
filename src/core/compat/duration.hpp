#pragma once

#include <chrono>
#include <ratio>

namespace encrypto::core::compat {

using nanoseconds = std::chrono::nanoseconds;
using microseconds = std::chrono::microseconds;
using milliseconds = std::chrono::milliseconds;
using seconds = std::chrono::seconds;
using minutes = std::chrono::minutes;
using hours = std::chrono::hours;

template<typename Rep, typename Period = std::ratio<1>>
using duration = std::chrono::duration<Rep, Period>;

template<typename ToDuration, typename Rep, typename Period>
constexpr ToDuration duration_cast(const duration<Rep, Period>& d) noexcept {
    return std::chrono::duration_cast<ToDuration>(d);
}

} // namespace encrypto::core::compat
