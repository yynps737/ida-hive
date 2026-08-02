cmake_minimum_required(VERSION 3.27)

# Accept either a CMake cache entry or the environment variable for IDASDK.
if(DEFINED IDASDK AND NOT DEFINED ENV{IDASDK})
    set(ENV{IDASDK} "${IDASDK}")
endif()
if(NOT DEFINED ENV{IDASDK})
    message(FATAL_ERROR "IDASDK must point to the IDA SDK root (repo root or src/).")
endif()

# Must precede project(): idasdk_init preselects MSVC so project() finds cl.exe.
# It also accepts either SDK layout, <root>/include or <root>/src/include.
set(_idasdk_init "$ENV{IDASDK}/src/cmake/idasdk_init.cmake")
if(NOT EXISTS "${_idasdk_init}")
    set(_idasdk_init "$ENV{IDASDK}/cmake/idasdk_init.cmake")
endif()
if(NOT EXISTS "${_idasdk_init}")
    message(FATAL_ERROR
        "Could not locate cmake/idasdk_init.cmake under $ENV{IDASDK}. "
        "IDA SDK 9.4 or newer is required; 9.2/9.3 shipped bootstrap.cmake instead.")
endif()
include("${_idasdk_init}")

project(ida_mcp_worker VERSION 0.1.0)
set(CMAKE_CXX_STANDARD 17)

find_package(idasdk REQUIRED)

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

# ida_add_idalib points RUNTIME_OUTPUT_DIRECTORY at IDABIN, which would write the
# worker into the IDA installation. Keep it in the build tree instead.
set_target_properties(ida_mcp_worker PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

# Header-only, so no install step is needed.
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
