// worker.cpp - IDA MCP Worker process
//
// Headless idalib process that reads JSON commands from stdin,
// calls IDA SDK APIs, and writes JSON results to stdout.
//
// Usage: ida_mcp_worker <binary_or_idb_path>

// nlohmann/json MUST come before IDA headers (pro.h redefines fgetc)
#include "pch.h"

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <auto.hpp>
#include <idalib.hpp>

#include "protocol.h"
#include "util.h"
#include "commands/cmd_core.h"
#include "commands/cmd_analysis.h"
#include "commands/cmd_memory.h"
#include "commands/cmd_modify.h"
#include "commands/cmd_search.h"
#include "commands/cmd_graph.h"
#include "commands/cmd_types.h"
#include "commands/cmd_stack.h"
#include "commands/cmd_composite.h"

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        qeprintf("Usage: %s <binary_or_idb_path>\n", argv[0]);
        return 1;
    }

    const char* input_path = argv[1];

    LOG("Initializing idalib...");

    int rc = init_library();
    if (rc != 0)
    {
        LOG("init_library() failed: %d", rc);
        return 1;
    }

    enable_console_messages(false);

    // Detect if input is a pre-analyzed .i64/.idb or a raw binary
    std::string path_str(input_path);
    bool is_idb = path_str.size() > 4 &&
        (path_str.substr(path_str.size() - 4) == ".i64" ||
         path_str.substr(path_str.size() - 4) == ".idb");

    LOG("Opening %s: %s", is_idb ? "database" : "binary", input_path);

    // .i64 = already analyzed, skip auto-analysis for speed
    rc = open_database(input_path, !is_idb);
    if (rc != 0)
    {
        LOG("open_database() failed: %d", rc);
        return 1;
    }

    if (!is_idb)
    {
        LOG("Waiting for auto-analysis...");
        auto_wait();
    }

    // Build the command dispatcher
    CommandDispatcher dispatcher;

    register_core_commands(dispatcher);
    register_analysis_commands(dispatcher);
    register_memory_commands(dispatcher);
    register_modify_commands(dispatcher);
    register_search_commands(dispatcher);
    register_graph_commands(dispatcher);
    register_type_commands(dispatcher);
    register_stack_commands(dispatcher);
    register_composite_commands(dispatcher);

    // Health check
    dispatcher.register_command("ping", [](const json& params) -> json {
        return {{"pong", true}};
    });

    // Shutdown
    dispatcher.register_command("shutdown", [](const json& params) -> json {
        std::cin.setstate(std::ios_base::eofbit);
        return {{"shutdown", true}};
    });

    // Signal ready to coordinator
    size_t func_count = get_func_qty();
    int seg_count = get_segm_qty();
    qstring procname = inf_get_procname();

    send_event("ready", {
        {"path",       input_path},
        {"processor",  procname.c_str()},
        {"functions",  func_count},
        {"segments",   seg_count},
    });

    LOG("Ready. %zu functions, %d segments. Entering command loop.",
        func_count, seg_count);

    dispatcher.run();

    LOG("Shutting down...");
    close_database(false);

    return 0;
}
