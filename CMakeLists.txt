cmake_minimum_required(VERSION 3.15)
project(EncryptoDrive
    VERSION 0.1.0
    DESCRIPTION "Secure file storage and synchronization system"
    LANGUAGES CXX
)

# Set default build type if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

# Enable testing project-wide
enable_testing()

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
find_package(GTest REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(SQLite3 REQUIRED)

# Add core library target
add_library(encrypto-core)

# Add subdirectories
add_subdirectory(src/core)
add_subdirectory(src/audit)
add_subdirectory(tests)

# Link audit with core
target_link_libraries(encrypto-core
    PUBLIC
    audit
)

# Set compiler flags
target_compile_features(encrypto-core PUBLIC cxx_std_17)
set_target_properties(encrypto-core PROPERTIES
    CXX_EXTENSIONS OFF
)

# Set compile options based on compiler
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(encrypto-core PRIVATE
        -Wall
        -Wextra
        -Werror
        -pedantic
        -Wconversion
        -Wsign-conversion
        -Wcast-align
        -Wformat=2
        -Wuninitialized
        -Wnull-dereference
        -Wdouble-promotion
        -fstack-protector-strong
    )
elseif(MSVC)
    target_compile_options(encrypto-core PRIVATE
        /W4
        /WX
        /permissive-
        /sdl
        /guard:cf
    )
endif()

# Generate package configuration
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_BINARY_DIR}/EncryptoDriveConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

# Install package configuration
install(EXPORT encrypto-targets
    FILE EncryptoDriveTargets.cmake
    NAMESPACE EncryptoDrive::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/EncryptoDrive
)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/EncryptoDriveConfig.cmake.in
    ${CMAKE_BINARY_DIR}/EncryptoDriveConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/EncryptoDrive
)
