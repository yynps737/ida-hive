cmake_minimum_required(VERSION 3.27)
project(ida_mcp_worker VERSION 0.1.0)
set(CMAKE_CXX_STANDARD 17)

# Include IDA SDK bootstrap
include($ENV{IDASDK}/src/cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

# Worker executable — idalib headless
ida_add_idalib(ida_mcp_worker
    TYPE EXECUTABLE
    SOURCES
        worker.cpp
        commands/cmd_core.cpp
        commands/cmd_analysis.cpp
        commands/cmd_memory.cpp
        commands/cmd_modify.cpp
        commands/cmd_search.cpp
        commands/cmd_graph.cpp
        commands/cmd_types.cpp
        commands/cmd_stack.cpp
        commands/cmd_composite.cpp
)

# nlohmann/json — header-only, fetch via CMake
include(FetchContent)
FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
)
FetchContent_MakeAvailable(json)
target_link_libraries(ida_mcp_worker PRIVATE nlohmann_json::nlohmann_json)

# idalib programs need IDA in PATH
if(MSVC)
    file(TO_NATIVE_PATH "${IDABIN}" IDABIN_NATIVE)
    set_target_properties(ida_mcp_worker PROPERTIES
        VS_DEBUGGER_ENVIRONMENT "PATH=${IDABIN_NATIVE};%PATH%"
    )
endif()
