add_library(audit
    auditlog.cpp
    auditlog.hpp
)

target_include_directories(audit PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
)

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(nlohmann_json REQUIRED)

target_link_libraries(audit PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    SQLite::SQLite3
    nlohmann_json::nlohmann_json
)

# Export symbols for modules that depend on audit
include(GenerateExportHeader)
generate_export_header(audit
    BASE_NAME AUDIT
    EXPORT_FILE_NAME ${CMAKE_BINARY_DIR}/include/audit_export.hpp
)
