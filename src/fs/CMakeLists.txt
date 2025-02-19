# Filesystem library target
target_sources(encrypto-fs PRIVATE
    fsops.cpp
    fusefs.cpp
)

# Filesystem library includes
target_include_directories(encrypto-fs
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${FUSE3_INCLUDE_DIRS}
)

# Filesystem library dependencies
target_link_libraries(encrypto-fs
    PUBLIC
        encrypto-core
        ${FUSE3_LIBRARIES}
    PRIVATE
        Threads::Threads
)

# Generate export header
include(GenerateExportHeader)
generate_export_header(encrypto-fs
    BASE_NAME ENCRYPTO_FS
    EXPORT_FILE_NAME fs_export.hpp
)

# Configure filesystem config header
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/fsconfig.hpp.in
    ${CMAKE_CURRENT_BINARY_DIR}/fsconfig.hpp
    @ONLY
)

# Set library properties
set_target_properties(encrypto-fs PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    OUTPUT_NAME "encrypto-fs"
    POSITION_INDEPENDENT_CODE ON
)

# Set compile definitions
target_compile_definitions(encrypto-fs PRIVATE
    ENCRYPTO_FS_EXPORTS
    FUSE_USE_VERSION=31
)

if(HAVE_SPLICE)
    target_compile_definitions(encrypto-fs PRIVATE
        HAVE_SPLICE
    )
endif()

if(HAVE_FALLOC)
    target_compile_definitions(encrypto-fs PRIVATE
        HAVE_FALLOC
    )
endif()

if(HAVE_XATTR)
    target_compile_definitions(encrypto-fs PRIVATE
        HAVE_XATTR
    )
endif()

if(HAVE_ACL)
    target_compile_definitions(encrypto-fs PRIVATE
        HAVE_ACL
    )
endif()

# Install filesystem library
install(TARGETS encrypto-fs
    EXPORT encrypto-targets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# Install headers
install(FILES
    fsops.hpp
    fusefs.hpp
    ${CMAKE_CURRENT_BINARY_DIR}/fs_export.hpp
    ${CMAKE_CURRENT_BINARY_DIR}/fsconfig.hpp
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/encrypto/fs
)
