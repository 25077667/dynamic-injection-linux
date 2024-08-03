add_executable(example simple.cpp)
target_link_libraries(example ${PROJECT_NAME})

add_library(helloworld SHARED to_be_injected.cpp)
