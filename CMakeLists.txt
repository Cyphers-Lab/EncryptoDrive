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

# Set up test environment
set(TEST_OUTPUT_DIR ${CMAKE_BINARY_DIR}/test-output)
set(TEST_DATA_DIR ${CMAKE_BINARY_DIR}/test-data)

# Configure test environment variables
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_config.h.in
    ${CMAKE_BINARY_DIR}/include/test_config.h
    @ONLY
)

# Include GNUInstallDirs for installation paths
include(GNUInstallDirs)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
find_package(GTest REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)

# Add core library target
add_library(encrypto-core)
set_property(TARGET encrypto-core PROPERTY POSITION_INDEPENDENT_CODE ON)

# Set up include directories
target_include_directories(encrypto-core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# Set up export macros
include(GenerateExportHeader)
generate_export_header(encrypto-core
    BASE_NAME ENCRYPTO_CORE
    EXPORT_FILE_NAME ${CMAKE_BINARY_DIR}/include/core/core_export.hpp
)

# Ensure the include/core directory exists
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/include/core)

# Add subdirectories
add_subdirectory(src/core)
add_subdirectory(src/audit)
add_subdirectory(src/auth)
add_subdirectory(src/fs)
add_subdirectory(src/gui)
add_subdirectory(tests)

# Link audit with core
target_link_libraries(encrypto-core
    PUBLIC
    audit
    ZLIB::ZLIB
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

# Install targets
install(TARGETS encrypto-core
    EXPORT encrypto-targets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
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

# Add uninstall target
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in
    ${CMAKE_BINARY_DIR}/cmake_uninstall.cmake
    @ONLY
)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_BINARY_DIR}/cmake_uninstall.cmake
)
