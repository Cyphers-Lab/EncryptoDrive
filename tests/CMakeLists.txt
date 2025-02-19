# Enable testing
enable_testing()

# Find GTest
find_package(GTest REQUIRED)

# Create test executable
add_executable(encrypto-tests
    core/integrity/merkletree_test.cpp
    core/version/fileversion_test.cpp
    core/version/versionstore_test.cpp
    core/crypto/signaturesystem_test.cpp
)

# Link dependencies
target_link_libraries(encrypto-tests
    PRIVATE
        encrypto-core
        GTest::GTest
        GTest::Main
)

# Set include paths
target_include_directories(encrypto-tests
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
)

# Add tests to CTest
add_test(NAME EncryptoTests COMMAND encrypto-tests)

# Configure test environment
set_tests_properties(EncryptoTests PROPERTIES
    ENVIRONMENT "ENCRYPTO_TEST_DIR=${CMAKE_BINARY_DIR}/test-output"
)

# Create test output directory
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/test-output)

# Set testing properties
set_target_properties(encrypto-tests PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
