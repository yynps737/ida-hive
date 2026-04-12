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

    // .i64 = already analyzed, raw binary = start auto-analysis in background
    rc = open_database(input_path, !is_idb);
    if (rc != 0)
    {
        LOG("open_database() failed: %d", rc);
        return 1;
    }

    // For raw binaries, do NOT call auto_wait() here.
    // Auto-analysis runs in IDA's internal background.
    // Commands are available immediately; AI can poll analysis_status.
    bool analyzing = !is_idb;
    if (analyzing)
    {
        LOG("Auto-analysis started in background (not blocking)");
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

    // ---- analysis_status (non-blocking) ----
    // Returns current auto-analysis state without blocking.
    // AI polls this to know when a raw binary is fully analyzed.
    dispatcher.register_command("analysis_status", [](const json& params) -> json {
        bool done = auto_is_ok();

        // get_auto_display gives us the current analysis address and queue type
        auto_display_t ad{};
        bool has_display = get_auto_display(&ad);

        json result = {
            {"done",       done},
            {"functions",  get_func_qty()},
            {"segments",   get_segm_qty()},
        };

        if (!done && has_display)
        {
            // Map atype_t to human-readable queue name
            const char* state_name = "unknown";
            switch (ad.type)
            {
                case AU_UNK:    state_name = "AU_UNK";    break;
                case AU_CODE:   state_name = "AU_CODE";   break;
                case AU_WEAK:   state_name = "AU_WEAK";   break;
                case AU_PROC:   state_name = "AU_PROC";   break;
                case AU_TAIL:   state_name = "AU_TAIL";   break;
                case AU_FCHUNK: state_name = "AU_FCHUNK"; break;
                case AU_USED:   state_name = "AU_USED";   break;
                case AU_USD2:   state_name = "AU_USD2";   break;
                case AU_TYPE:   state_name = "AU_TYPE";   break;
                case AU_LIBF:   state_name = "AU_LIBF";   break;
                case AU_LBF2:   state_name = "AU_LBF2";   break;
                case AU_LBF3:   state_name = "AU_LBF3";   break;
                case AU_CHLB:   state_name = "AU_CHLB";   break;
                case AU_FINAL:  state_name = "AU_FINAL";  break;
                default:        state_name = "other";     break;
            }

            result["state"]      = state_name;
            result["current_ea"] = ea_hex(ad.ea);

            // Map idastate_t
            const char* ida_state = "unknown";
            switch (ad.state)
            {
                case st_Ready:   ida_state = "ready";   break;
                case st_Think:   ida_state = "think";   break;
                case st_Waiting: ida_state = "waiting"; break;
                case st_Work:    ida_state = "work";    break;
                default:         ida_state = "unknown"; break;
            }
            result["ida_state"] = ida_state;
        }

        return result;
    });

    // ---- wait_analysis (blocking with timeout + progress events) ----
    // Blocks until auto-analysis completes or timeout is reached.
    // Sends periodic "analysis_progress" events to coordinator.
    // params: {max_seconds?: int}  default=300, max=600
    dispatcher.register_command("wait_analysis", [](const json& params) -> json {
        if (auto_is_ok())
        {
            return {
                {"done",      true},
                {"elapsed",   0.0},
                {"functions", get_func_qty()},
                {"segments",  get_segm_qty()},
            };
        }

        int max_seconds = params.value("max_seconds", 300);
        if (max_seconds < 1)   max_seconds = 1;
        if (max_seconds > 600) max_seconds = 600;

        LOG("wait_analysis: waiting up to %d seconds", max_seconds);

        auto start = std::chrono::steady_clock::now();
        int last_report = 0;

        while (true)
        {
            // Poll auto_is_ok — non-blocking check
            if (auto_is_ok())
            {
                double elapsed = std::chrono::duration<double>(
                    std::chrono::steady_clock::now() - start).count();

                send_event("analysis_progress", {
                    {"done",      true},
                    {"elapsed",   elapsed},
                    {"functions", get_func_qty()},
                    {"segments",  get_segm_qty()},
                });

                return {
                    {"done",      true},
                    {"elapsed",   elapsed},
                    {"functions", get_func_qty()},
                    {"segments",  get_segm_qty()},
                };
            }

            // Check timeout
            double elapsed = std::chrono::duration<double>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed >= max_seconds)
            {
                return {
                    {"done",      false},
                    {"elapsed",   elapsed},
                    {"timeout",   true},
                    {"functions", get_func_qty()},
                    {"segments",  get_segm_qty()},
                };
            }

            // Send progress event every 2 seconds
            int current_sec = (int)elapsed;
            if (current_sec >= last_report + 2)
            {
                last_report = current_sec;

                auto_display_t ad{};
                json progress = {
                    {"done",      false},
                    {"elapsed",   elapsed},
                    {"functions", get_func_qty()},
                    {"segments",  get_segm_qty()},
                };
                if (get_auto_display(&ad))
                    progress["current_ea"] = ea_hex(ad.ea);

                send_event("analysis_progress", progress);
            }

            // Sleep 500ms between polls — cooperative, not busy-wait
            qsleep(500);
        }
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
        {"analyzing",  analyzing},
    });

    LOG("Ready. %zu functions, %d segments. Entering command loop.",
        func_count, seg_count);

    dispatcher.run();

    LOG("Shutting down...");
    close_database(false);

    return 0;
}
