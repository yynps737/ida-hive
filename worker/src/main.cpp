// Must stay first; see pch.h for the macro collision it works around.
#include "ida_hive/pch.hpp"

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <auto.hpp>
#include <idalib.hpp>
#include <fpro.h>

#include "ida_hive/protocol.hpp"
#include "ida_hive/commands.hpp"
#include "ida_hive/util.hpp"

namespace ida_hive {
// Declared in util.hpp.
std::string g_original_input;
std::string g_db_dir;
}  // namespace ida_hive

using namespace ida_hive;

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        qeprintf("Usage: %s <binary_or_idb_path> [private_db_dir]\n", argv[0]);
        return 1;
    }

    const char* input_path = argv[1];
    // Unique per worker when the coordinator supplies it, which keeps IDA's database
    // and lock files out of the input's directory. Empty runs in place.
    std::string db_dir = (argc >= 3) ? argv[2] : "";

    g_original_input = input_path;
    g_db_dir = db_dir;

    LOG("Initializing idalib...");

    int rc = init_library();
    if (rc != 0)
    {
        send_event("init_error", {
            {"stage",   "init_library"},
            {"code",    rc},
            {"message", "idalib init_library() failed (check IDA license/activation)"},
        });
        LOG("init_library() failed: %d", rc);
        return 1;
    }

    enable_console_messages(false);

    std::string path_str(input_path);
    bool is_idb = has_db_extension(path_str);

    // A database and a raw binary reach the private dir by different routes: the
    // former is copied into it, the latter redirects its output there.
    std::string open_path = input_path;   // what open_database loads
    std::string open_args;                // IDA CLI args (e.g. -odb)
    if (!db_dir.empty())
    {
        if (is_idb)
        {
            // IDA locks a database on open, so workers cannot share one file. Each
            // opens its own copy. db_dir is absolute, so dest is cwd-independent.
            std::string ext = path_str.substr(path_str.size() - 4);
            std::string dest = db_dir + "/db" + ext;
            int crc = qcopyfile(input_path, dest.c_str(), true);
            if (crc != 0)
            {
                send_event("init_error", {
                    {"stage",   "copy_database"},
                    {"code",    crc},
                    {"message", "failed to copy database into private dir"},
                    {"path",    input_path},
                });
                LOG("qcopyfile(%s -> %s) failed: %d", input_path, dest.c_str(), crc);
                return 1;
            }
            open_path = dest;
        }
        else
        {
            // chdir + bare "-odb", never "-o<abspath>/db": IDA re-tokenizes the args
            // string on spaces and treats '\' as an escape, which corrupts absolute
            // paths. "-odb" contains neither. The positional input path is exempt.
            if (qchdir(db_dir.c_str()) != 0)
            {
                send_event("init_error", {
                    {"stage",   "chdir"},
                    {"message", "failed to chdir into private db dir"},
                    {"path",    db_dir},
                });
                LOG("qchdir(%s) failed", db_dir.c_str());
                return 1;
            }
            open_args = "-odb";
        }
    }

    LOG("Opening %s: %s%s%s", is_idb ? "database" : "binary", input_path,
        open_args.empty() ? "" : " ", open_args.c_str());

    // The second argument runs auto-analysis, and does so to completion: for a raw
    // binary this call is where the minutes go.
    rc = open_database(open_path.c_str(), !is_idb,
                       open_args.empty() ? nullptr : open_args.c_str());
    if (rc != 0)
    {
        send_event("init_error", {
            {"stage",   "open_database"},
            {"code",    rc},
            {"message", "open_database() failed (file unreadable, locked, or unsupported)"},
            {"path",    input_path},
        });
        LOG("open_database() failed: %d", rc);
        return 1;
    }

    // Records that the input was a raw binary, not that analysis is still running —
    // open_database above already finished it. The coordinator drops this field from
    // list_instances for that reason.
    bool analyzing = !is_idb;
    if (analyzing)
    {
        LOG("Initial auto-analysis complete");
    }

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
    register_flow_commands(dispatcher);
    register_microcode_commands(dispatcher);
    register_dscu_commands(dispatcher);
    register_string_commands(dispatcher);
    register_indexer_commands(dispatcher);
    register_signature_commands(dispatcher);
    register_offset_commands(dispatcher);
    register_database_commands(dispatcher);

    dispatcher.register_command("ping", [](const json& params) -> json {
        return {{"pong", true}};
    });

    // Faking EOF ends dispatcher.run(), which unwinds main() and closes the database.
    dispatcher.register_command("shutdown", [](const json& params) -> json {
        std::cin.setstate(std::ios_base::eofbit);
        return {{"shutdown", true}};
    });

    // Never blocks. Reports the analysis queues as they stand; work queued after the
    // initial pass stays pending until wait_analysis drives it.
    dispatcher.register_command("analysis_status", [](const json& params) -> json {
        bool done = auto_is_ok();

        auto_display_t ad{};
        bool has_display = get_auto_display(&ad);

        json result = {
            {"done",       done},
            {"functions",  get_func_qty()},
            {"segments",   get_segm_qty()},
        };

        if (!done && has_display)
        {
            // atype_t: which analysis queue is being drained.
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
                case AU_NONE:   state_name = "none";      break;
                default:        state_name = "other";     break;
            }

            result["state"]      = state_name;
            result["current_ea"] = ea_hex(ad.ea);

            // idastate_t: what the kernel itself is doing.
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

    // Blocks until analysis settles or max_seconds elapses (default 300, capped 600),
    // emitting analysis_progress events meanwhile. Returns at once in the common case,
    // since open_database already ran the initial pass.
    //
    // The deadline is checked between drain passes, not during one: a pass runs on this
    // thread and cannot be interrupted. It is bounded by the queued work, not by the
    // size of the database.
    dispatcher.register_command("wait_analysis", [](const json& params) -> json {
        if (!auto_is_ok())
            auto_wait_range(inf_get_min_ea(), inf_get_max_ea());

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

            // idalib has no background analysis thread: the queues are drained only
            // when the host asks for it. Polling auto_is_ok() alone would therefore
            // spin to the timeout on anything queued after the initial pass, such as
            // the re-analysis a type change schedules.
            if (auto_wait_range(inf_get_min_ea(), inf_get_max_ea()) == 0 && !auto_is_ok())
                auto_wait();  // Queued outside the database range.
        }
    });

    // The coordinator's start() blocks on this event.
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
