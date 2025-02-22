# Core tests
add_executable(core_tests
    keyrotation_test.cpp
)

target_link_libraries(core_tests
    PRIVATE
        encrypto-core
        GTest::gtest
        GTest::gtest_main
        Threads::Threads
)

target_include_directories(core_tests
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
)

# Add the test
add_test(NAME core_tests COMMAND core_tests)
