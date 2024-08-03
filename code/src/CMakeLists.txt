set(INCL 
    ${CMAKE_CURRENT_SOURCE_DIR})

set(SRC 
    DynamicLinkingLinux.cpp
    ProcessHandler.cpp
    Ptrace.cpp
    MemoryStatus.cpp
    FileMapping.cpp
    MyLibc.cpp
)

add_library(${PROJECT_NAME} SHARED ${SRC})

target_include_directories(${PROJECT_NAME} PUBLIC ${INCL})
