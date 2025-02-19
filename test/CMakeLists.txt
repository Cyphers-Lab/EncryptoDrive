# Enable testing
enable_testing()

# Find GTest
find_package(GTest REQUIRED)

# Add test directories
add_subdirectory(core)

# Configure test options
set(GTEST_CATCH_EXCEPTIONS OFF)
set(GTEST_BREAK_ON_FAILURE ON)

# Common test settings
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_definitions(ENCRYPTO_TEST_DEBUG)
endif()

# Set test output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/test)
