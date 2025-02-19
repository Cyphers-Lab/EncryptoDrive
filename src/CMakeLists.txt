# Add subdirectories
add_subdirectory(core)
add_subdirectory(fs)
add_subdirectory(auth)
add_subdirectory(gui)
add_subdirectory(keymanagement)

# Main application sources
target_sources(encrypto PRIVATE
    main.cpp
)

# Main application dependencies
target_link_libraries(encrypto PRIVATE
    encrypto-core
    encrypto-fs
    encrypto-auth
    encrypto-gui
    encrypto-keymanagement
    Qt6::Core
    Qt6::Widgets
)

# Main application properties
set_target_properties(encrypto PROPERTIES
    WIN32_EXECUTABLE TRUE
    MACOSX_BUNDLE TRUE
    OUTPUT_NAME "encrypto"
)

# Main application installation
install(TARGETS encrypto
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    BUNDLE DESTINATION .
)
