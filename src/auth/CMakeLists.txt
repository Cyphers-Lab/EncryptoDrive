# Authentication library target
target_sources(encrypto-auth PRIVATE
    auth.cpp
    passwordvalidator.cpp
)

# Authentication library includes
target_include_directories(encrypto-auth
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Authentication library dependencies
target_link_libraries(encrypto-auth
    PUBLIC
        encrypto-core
    PRIVATE
        Threads::Threads
)

# Generate export header
include(GenerateExportHeader)
generate_export_header(encrypto-auth
    BASE_NAME ENCRYPTO_AUTH
    EXPORT_FILE_NAME auth_export.hpp
)

# Set library properties
set_target_properties(encrypto-auth PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    OUTPUT_NAME "encrypto-auth"
    POSITION_INDEPENDENT_CODE ON
)

# Set compile definitions
target_compile_definitions(encrypto-auth PRIVATE
    ENCRYPTO_AUTH_EXPORTS
)

# Install authentication library
install(TARGETS encrypto-auth
    EXPORT encrypto-targets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# Install headers
install(FILES
    auth.hpp
    passwordvalidator.hpp
    ${CMAKE_CURRENT_BINARY_DIR}/auth_export.hpp
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/encrypto/auth
)
