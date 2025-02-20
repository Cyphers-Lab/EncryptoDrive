add_library(audit
    auditlog.cpp
    auditlog.hpp
)

# Add target to export set
set_property(TARGET audit PROPERTY EXPORT_NAME audit)
install(TARGETS audit
    EXPORT encrypto-targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

target_include_directories(audit PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
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
