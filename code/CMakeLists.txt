cmake_minimum_required(VERSION 3.10)

set(PROJECT_NAME "DynamicLinkingLinux")
project(${PROJECT_NAME})

set(CMAKE_CXX_STANDARD 17)

include_directories(
    include
    ${CMAKE_SOURCE_DIR}
)

# set color for ninja
if(UNIX AND NOT APPLE)
    add_compile_options(-fdiagnostics-color=always)
endif()

# turn on all warnings
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
# suppress -Wc++98-compat
    add_compile_options(-Weverything -Wno-c++98-compat)
endif()

add_subdirectory(src)
add_subdirectory(example)

# Default enable testing
option(ENABLE_TESTS "Enable test building" ON)

if (ENABLE_TESTS)
    add_definitions(-DUNIT_TEST)

    include(FetchContent)
    # use latest googletest
    FetchContent_Declare(
      googletest
      GIT_REPOSITORY https://github.com/google/googletest.git
      GIT_TAG        v1.15.2
    )
    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    enable_testing()
    include(GoogleTest)

    include(CTest)
    add_subdirectory(tests)
endif()