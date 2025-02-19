# Create keymanagement library
add_library(encrypto-keymanagement
    keybackup.cpp
    publickeystore.cpp
    sharemanager.cpp
)

# Include directories
target_include_directories(encrypto-keymanagement
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Find SQLite3
find_package(SQLite3 REQUIRED)

# Link dependencies
target_link_libraries(encrypto-keymanagement
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        SQLite3::SQLite3
)

# Set library properties
set_target_properties(encrypto-keymanagement PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)
