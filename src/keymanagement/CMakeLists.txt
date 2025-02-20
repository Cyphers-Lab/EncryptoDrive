# Add library target
add_library(encrypto-keymanagement)

# Key management library sources
target_sources(encrypto-keymanagement PRIVATE
    keybackup.cpp
    publickeystore.cpp
    sharemanager.cpp
    shareprotocol.cpp
)

# Include directories
target_include_directories(encrypto-keymanagement
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(nlohmann_json REQUIRED)

# Library dependencies
target_link_libraries(encrypto-keymanagement
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        SQLite::SQLite3
        nlohmann_json::nlohmann_json
)

# Set target properties
set_target_properties(encrypto-keymanagement PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

# Export header configuration
include(GenerateExportHeader)
generate_export_header(encrypto-keymanagement
    BASE_NAME KEYMANAGEMENT
    EXPORT_FILE_NAME ${CMAKE_BINARY_DIR}/include/keymanagement_export.hpp
)

# Install the library
install(TARGETS encrypto-keymanagement
    EXPORT encrypto-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install headers
install(FILES
    ${CMAKE_SOURCE_DIR}/include/encryptodrive/keymanagement/keybackup.hpp
    ${CMAKE_SOURCE_DIR}/include/encryptodrive/keymanagement/publickeystore.hpp
    ${CMAKE_SOURCE_DIR}/include/encryptodrive/keymanagement/sharemanager.hpp
    ${CMAKE_SOURCE_DIR}/include/encryptodrive/keymanagement/shareprotocol.hpp
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/encryptodrive/keymanagement
)
