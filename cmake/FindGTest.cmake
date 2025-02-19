# Try to find GTest and GMock
#
# The following variables are optionally searched for defaults
#  GTEST_ROOT:            Base directory where all GTest components are found
#
# The following are set after configuration is done:
#  GTEST_FOUND            - True if GTest and GMock are found
#  GTest::gtest          - The Google Test library
#  GTest::gtest_main     - The Google Test main() library
#  GTest::gmock          - The Google Mock library
#  GTest::gmock_main     - The Google Mock main() library

include(FindPackageHandleStandardArgs)

# First try pkg-config
find_package(PkgConfig QUIET)
pkg_check_modules(PC_GTEST QUIET gtest)
pkg_check_modules(PC_GMOCK QUIET gmock)

# Set search paths
set(_GTEST_SEARCH_PATHS
    ${GTEST_ROOT}
    $ENV{GTEST_ROOT}
    /usr
    /usr/local
)

# Find include directory
find_path(GTEST_INCLUDE_DIR
    NAMES gtest/gtest.h
    PATHS ${_GTEST_SEARCH_PATHS}
    PATH_SUFFIXES include
    HINTS ${PC_GTEST_INCLUDEDIR}
)

# Find libraries
find_library(GTEST_LIBRARY
    NAMES gtest
    PATHS ${_GTEST_SEARCH_PATHS}
    PATH_SUFFIXES lib lib64
    HINTS ${PC_GTEST_LIBDIR}
)

find_library(GTEST_MAIN_LIBRARY
    NAMES gtest_main
    PATHS ${_GTEST_SEARCH_PATHS}
    PATH_SUFFIXES lib lib64
    HINTS ${PC_GTEST_LIBDIR}
)

find_library(GMOCK_LIBRARY
    NAMES gmock
    PATHS ${_GTEST_SEARCH_PATHS}
    PATH_SUFFIXES lib lib64
    HINTS ${PC_GMOCK_LIBDIR}
)

find_library(GMOCK_MAIN_LIBRARY
    NAMES gmock_main
    PATHS ${_GTEST_SEARCH_PATHS}
    PATH_SUFFIXES lib lib64
    HINTS ${PC_GMOCK_LIBDIR}
)

# Set required variables for find_package_handle_standard_args
find_package_handle_standard_args(GTest
    REQUIRED_VARS
        GTEST_LIBRARY
        GTEST_INCLUDE_DIR
    VERSION_VAR GTEST_VERSION
)

# Create imported targets
if(GTEST_FOUND AND NOT TARGET GTest::gtest)
    add_library(GTest::gtest UNKNOWN IMPORTED)
    set_target_properties(GTest::gtest PROPERTIES
        IMPORTED_LOCATION "${GTEST_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${GTEST_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES Threads::Threads
    )
endif()

if(GTEST_FOUND AND NOT TARGET GTest::gtest_main)
    add_library(GTest::gtest_main UNKNOWN IMPORTED)
    set_target_properties(GTest::gtest_main PROPERTIES
        IMPORTED_LOCATION "${GTEST_MAIN_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${GTEST_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES "GTest::gtest"
    )
endif()

if(GMOCK_LIBRARY AND NOT TARGET GTest::gmock)
    add_library(GTest::gmock UNKNOWN IMPORTED)
    set_target_properties(GTest::gmock PROPERTIES
        IMPORTED_LOCATION "${GMOCK_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${GTEST_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES "GTest::gtest"
    )
endif()

if(GMOCK_MAIN_LIBRARY AND NOT TARGET GTest::gmock_main)
    add_library(GTest::gmock_main UNKNOWN IMPORTED)
    set_target_properties(GTest::gmock_main PROPERTIES
        IMPORTED_LOCATION "${GMOCK_MAIN_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${GTEST_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES "GTest::gmock"
    )
endif()

mark_as_advanced(
    GTEST_INCLUDE_DIR
    GTEST_LIBRARY
    GTEST_MAIN_LIBRARY
    GMOCK_LIBRARY
    GMOCK_MAIN_LIBRARY
)
