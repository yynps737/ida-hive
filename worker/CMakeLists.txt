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

project(ida_mcp_worker VERSION 1.0.3)

# Mirrors the SDK's own src/CMakeLists.txt. CXX_EXTENSIONS and CXX_STANDARD_REQUIRED
# are deliberately left at their defaults, matching how IDA itself is compiled;
# idasdkConfig.cmake already makes cxx_std_17 a hard requirement on anything that
# links the SDK.
set(CMAKE_CXX_STANDARD 17)

find_package(idasdk REQUIRED)

ida_add_idalib(ida_mcp_worker
    TYPE EXECUTABLE
    SOURCES
        src/main.cpp
        src/commands/cmd_core.cpp
        src/commands/cmd_analysis.cpp
        src/commands/cmd_memory.cpp
        src/commands/cmd_modify.cpp
        src/commands/cmd_search.cpp
        src/commands/cmd_graph.cpp
        src/commands/cmd_types.cpp
        src/commands/cmd_stack.cpp
        src/commands/cmd_composite.cpp
        src/commands/cmd_flow.cpp
        src/commands/cmd_microcode.cpp
        src/commands/cmd_dscu.cpp
        src/commands/cmd_strings.cpp
        src/commands/cmd_indexer.cpp
        src/commands/cmd_signatures.cpp
        src/commands/cmd_offset.cpp
        src/commands/cmd_database.cpp
)

# Sources include their own headers as <ida_hive/...>, the same spelling a consumer
# would use, so the path never depends on where a .cpp sits in the tree.
target_include_directories(ida_mcp_worker PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")

# ida_add_idalib appends -w to silence the SDK headers, which also silences ours.
# Re-enabling afterwards wins on GCC and MSVC alike, since the later flag applies;
# SDK and nlohmann headers arrive through -isystem and stay quiet regardless.
option(IDA_HIVE_WARNINGS "Enable compiler warnings for ida-hive sources" ON)
if(IDA_HIVE_WARNINGS)
    if(MSVC)
        target_compile_options(ida_mcp_worker PRIVATE /W4)
    else()
        target_compile_options(ida_mcp_worker PRIVATE -Wall -Wextra)
    endif()
endif()

# ida_add_idalib points RUNTIME_OUTPUT_DIRECTORY at IDABIN, which would write the
# worker into the IDA installation. Keep it in the build tree instead.
set_target_properties(ida_mcp_worker PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

# Multi-config generators append the configuration to the output directory, so the
# path differs between MSVC and a single-config build. Packaging must not guess at
# it: these files record where the binary actually landed, and the release workflow
# reads them.
#
# OUTPUT must carry $<CONFIG> as well. Without it every configuration would write
# the same file and the last one generated would win — on MSVC that is Debug, which
# is not the configuration being built.
file(GENERATE
    OUTPUT "${CMAKE_BINARY_DIR}/worker-path-$<CONFIG>.txt"
    CONTENT "$<TARGET_FILE:ida_mcp_worker>")

# Single-config generators have exactly one configuration, so a stable name is safe
# there and keeps the Linux packaging step simple.
if(NOT CMAKE_CONFIGURATION_TYPES)
    file(GENERATE
        OUTPUT "${CMAKE_BINARY_DIR}/worker-path.txt"
        CONTENT "$<TARGET_FILE:ida_mcp_worker>")
endif()

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
