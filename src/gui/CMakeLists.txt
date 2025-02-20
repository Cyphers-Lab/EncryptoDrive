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

# Find Qt6 and its components
find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)

# Add GUI executable
add_executable(encrypto-gui
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
    "-Wl,-Bstatic -lpthread -Wl,-Bdynamic"
)

# Get Qt include directories
get_target_property(QtCore_INCLUDE_DIRS Qt6::Core INTERFACE_INCLUDE_DIRECTORIES)
get_target_property(QtGui_INCLUDE_DIRS Qt6::Gui INTERFACE_INCLUDE_DIRECTORIES)
get_target_property(QtWidgets_INCLUDE_DIRS Qt6::Widgets INTERFACE_INCLUDE_DIRECTORIES)

# Setup include directories
target_include_directories(encrypto-gui PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${QtCore_INCLUDE_DIRS}
    ${QtGui_INCLUDE_DIRS}
    ${QtWidgets_INCLUDE_DIRS}
)

# Enable Qt features
target_compile_features(encrypto-gui PRIVATE cxx_std_17)
target_compile_definitions(encrypto-gui PRIVATE
    $<$<CONFIG:Debug>:QT_DEBUG>
    $<$<NOT:$<CONFIG:Debug>>:QT_NO_DEBUG>
    QT_USE_QSTRINGBUILDER
)

# Set properties
set_target_properties(encrypto-gui PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    BUILD_WITH_INSTALL_RPATH TRUE
    INSTALL_RPATH "/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu"
    SKIP_BUILD_RPATH FALSE
)

# Create keys directory
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/keys)
