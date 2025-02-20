# Find FUSE3
find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE3 REQUIRED fuse3)

# Create filesystem library target
add_library(encrypto-fs SHARED)

# Add sources
target_sources(encrypto-fs PRIVATE
    fsops.cpp
    fusefs.cpp
    securedelete.cpp
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

# Feature detection
include(CheckSymbolExists)
check_symbol_exists(splice "fcntl.h" HAVE_SPLICE)
check_symbol_exists(copy_file_range "fcntl.h" HAVE_COPY_FILE_RANGE)
check_symbol_exists(fallocate "fcntl.h" HAVE_FALLOC)
check_symbol_exists(posix_fallocate "fcntl.h" HAVE_POSIX_FALLOCATE)
check_symbol_exists(setxattr "sys/xattr.h" HAVE_SETXATTR)
check_symbol_exists(acl_get_file "sys/acl.h" HAVE_ACL)
check_symbol_exists(io_setup "libaio.h" HAVE_LIBAIO)

# Set default values for features not found
if(NOT HAVE_SPLICE)
    set(HAVE_SPLICE false)
endif()
if(NOT HAVE_COPY_FILE_RANGE)
    set(HAVE_COPY_FILE_RANGE false)
endif()
if(NOT HAVE_FALLOC)
    set(HAVE_FALLOC false)
endif()
if(NOT HAVE_POSIX_FALLOCATE)
    set(HAVE_POSIX_FALLOCATE false)
endif()
if(NOT HAVE_SETXATTR)
    set(HAVE_SETXATTR false)
endif()
if(NOT HAVE_ACL)
    set(HAVE_ACL false)
endif()
if(NOT HAVE_LIBAIO)
    set(HAVE_LIBAIO false)
endif()

# Set FUSE configuration
set(FUSE_API_VERSION 31)
set(FUSE_MOUNT_PROG "${FUSE3_PREFIX}/bin/mount.fuse3")
set(FUSE_UNMOUNT_PROG "${FUSE3_PREFIX}/bin/fusermount3")

# Set default paths
set(ENCRYPTO_MOUNT_DIR "/mnt/encrypto")
set(ENCRYPTO_VOLUMES_DIR "~/.local/share/encrypto/volumes")
set(ENCRYPTO_METADATA_DIR "~/.local/share/encrypto/metadata")
set(ENCRYPTO_TEMP_DIR "/tmp/encrypto")

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
    securedelete.hpp
    ${CMAKE_CURRENT_BINARY_DIR}/fs_export.hpp
    ${CMAKE_CURRENT_BINARY_DIR}/fsconfig.hpp
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/encrypto/fs
)
