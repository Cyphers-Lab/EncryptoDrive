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
        ${CMAKE_BINARY_DIR}/include
        ${CMAKE_SOURCE_DIR}/tests
)

# Add tests to CTest
add_test(NAME EncryptoTests 
         COMMAND encrypto-tests
         WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# Configure test environment
set_tests_properties(EncryptoTests PROPERTIES
    ENVIRONMENT "TEST_OUTPUT_DIR=${TEST_OUTPUT_DIR};TEST_DATA_DIR=${TEST_DATA_DIR};GTEST_COLOR=1"
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

# Create test directories with proper permissions
file(MAKE_DIRECTORY ${TEST_OUTPUT_DIR})
file(MAKE_DIRECTORY ${TEST_DATA_DIR})
execute_process(
    COMMAND chmod -R 777 ${TEST_OUTPUT_DIR} ${TEST_DATA_DIR}
)

# Set testing properties
set_target_properties(encrypto-tests PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
