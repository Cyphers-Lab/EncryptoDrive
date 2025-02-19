# GUI Library
set(ENCRYPTO_GUI_SOURCES
    main.cpp
    windows/mainwindow.cpp
    dialogs/passworddialog.cpp
    dialogs/mountdialog.cpp
    widgets/drivelist.cpp
)

set(ENCRYPTO_GUI_HEADERS
    windows/mainwindow.hpp
    dialogs/passworddialog.hpp
    dialogs/mountdialog.hpp
    widgets/drivelist.hpp
)

set(ENCRYPTO_GUI_UIS
    windows/mainwindow.ui
    dialogs/passworddialog.ui
    dialogs/mountdialog.ui
)

# Find Qt6
find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)

# Add GUI library
add_library(encrypto-gui SHARED
    ${ENCRYPTO_GUI_SOURCES}
    ${ENCRYPTO_GUI_HEADERS}
    ${ENCRYPTO_GUI_UIS}
    resources.qrc
)

# Set up Qt features
set_target_properties(encrypto-gui PROPERTIES
    AUTOMOC ON
    AUTOUIC ON
    AUTORCC ON
)

# Setup Qt
target_link_libraries(encrypto-gui PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    encrypto-core
    encrypto-fs
    encrypto-auth
)

# Include directories
target_include_directories(encrypto-gui
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/..
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
)

# Set properties
set_target_properties(encrypto-gui PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
