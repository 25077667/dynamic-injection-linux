file(GLOB_RECURSE TEST_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

set(INCL 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

foreach(source ${TEST_SOURCES})
    message(STATUS "Adding test: ${source}")
    # Get the name of the source file without extension and prefix it with "t_"
    get_filename_component(name ${source} NAME_WE)
    add_executable(t_${name} ${source})
    target_link_libraries(t_${name} PRIVATE ${PROJECT_NAME} GTest::gtest_main GTest::gmock_main)
    target_include_directories(t_${name} PUBLIC ${INCL})
    gtest_discover_tests(t_${name})
endforeach()