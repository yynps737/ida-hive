cmake_minimum_required(VERSION 3.27)
project(ida_mcp_worker VERSION 0.1.0)
set(CMAKE_CXX_STANDARD 17)

# Accept either a CMake cache entry or the environment variable for IDASDK.
if(DEFINED IDASDK AND NOT DEFINED ENV{IDASDK})
    set(ENV{IDASDK} "${IDASDK}")
elseif(NOT DEFINED IDASDK AND DEFINED ENV{IDASDK})
    set(IDASDK "$ENV{IDASDK}")
endif()

if(NOT DEFINED IDASDK AND NOT DEFINED ENV{IDASDK})
    message(FATAL_ERROR "IDASDK must point to the IDA SDK root (repo root or src/).")
endif()

set(_ida_sdk_bootstrap_root "$ENV{IDASDK}")
if(NOT _ida_sdk_bootstrap_root AND DEFINED IDASDK)
    set(_ida_sdk_bootstrap_root "${IDASDK}")
endif()

if(EXISTS "${_ida_sdk_bootstrap_root}/src/cmake/bootstrap.cmake")
    include("${_ida_sdk_bootstrap_root}/src/cmake/bootstrap.cmake")
elseif(EXISTS "${_ida_sdk_bootstrap_root}/cmake/bootstrap.cmake")
    include("${_ida_sdk_bootstrap_root}/cmake/bootstrap.cmake")
else()
    message(FATAL_ERROR "Could not locate ida-cmake bootstrap under: ${_ida_sdk_bootstrap_root}")
endif()

# bootstrap normalizes the public GitHub SDK layout to .../src. Mirror that
# back into the cache so re-configures keep using the canonical tree.
set(IDASDK "$ENV{IDASDK}" CACHE PATH "Path to the IDA SDK root" FORCE)
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
