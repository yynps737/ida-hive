#include "ida_hive/pch.hpp"

#include <ida.hpp>
#include <idp.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <auto.hpp>
#include <loader.hpp>
#include <idalib.hpp>
#include <fpro.h>

#include "ida_hive/commands.hpp"
#include "ida_hive/util.hpp"

namespace ida_hive {
namespace {

json cmd_get_info(const json &params)
{
    qstring procname = inf_get_procname();
    return {
        {"processor",  procname.c_str()},
        {"bits",       inf_is_64bit() ? 64 : 32},
        {"entry",      ea_hex(inf_get_start_ip())},
        {"min_ea",     ea_hex(inf_get_min_ea())},
        {"max_ea",     ea_hex(inf_get_max_ea())},
        {"func_count", get_func_qty()},
        {"seg_count",  get_segm_qty()},
    };
}

json cmd_list_funcs(const json &params)
{
    size_t offset = params.value("offset", 0);
    size_t limit  = params.value("limit", 100);
    std::string filter = params.value("filter", std::string{});

    json funcs = json::array();
    size_t total = get_func_qty();
    size_t matched = 0;
    size_t skipped = 0;

    for (size_t i = 0; i < total && funcs.size() < limit; i++)
    {
        func_t* f = getn_func(i);
        if (!f) continue;

        qstring name;
        get_func_name(&name, f->start_ea);

        if (!filter.empty() && std::string(name.c_str()).find(filter) == std::string::npos)
            continue;

        matched++;
        if (skipped < offset) { skipped++; continue; }

        funcs.push_back({
            {"ea",   ea_hex(f->start_ea)},
            {"name", name.c_str()},
            {"size", (size_t)(f->end_ea - f->start_ea)},
        });
    }

    return {{"functions", funcs}, {"total", total}, {"matched", matched}};
}

json cmd_list_segments(const json &params)
{
    json segs = json::array();
    int qty = get_segm_qty();

    for (int i = 0; i < qty; i++)
    {
        segment_t* seg = getnseg(i);
        if (!seg) continue;

        qstring seg_name, seg_class;
        get_segm_name(&seg_name, seg);
        get_segm_class(&seg_class, seg);

        segs.push_back({
            {"name",  seg_name.c_str()},
            {"class", seg_class.c_str()},
            {"start", ea_hex(seg->start_ea)},
            {"end",   ea_hex(seg->end_ea)},
            {"size",  (size_t)(seg->end_ea - seg->start_ea)},
        });
    }

    return {{"segments", segs}};
}

json cmd_lookup_func(const json &params)
{
    // Accept either "ea" (current schema) or "target" (legacy callers).
    std::string target;
    if (params.contains("ea") && !params["ea"].is_null())
        target = params["ea"].get<std::string>();
    else
        target = params.at("target").get<std::string>();

    // Shares parse_ea's resolver, so lookup_func and decompile accept the same names.
    ea_t ea = BADADDR;
    try { ea = (ea_t)std::stoull(target, nullptr, 0); } catch (...) {}

    if (ea == BADADDR || !get_func(ea))
        ea = resolve_name_ea(target);

    if (ea == BADADDR)
        throw std::runtime_error("Not found: " + target);

    func_t* f = get_func(ea);
    if (!f)
        throw std::runtime_error("No function at: " + target);

    qstring name;
    get_func_name(&name, f->start_ea);

    return {
        {"ea",   ea_hex(f->start_ea)},
        {"name", name.c_str()},
        {"size", (size_t)(f->end_ea - f->start_ea)},
    };
}

json cmd_save_idb(const json &params)
{
    std::string outpath;
    if (params.contains("output_path") && !params["output_path"].is_null())
    {
        outpath = params["output_path"].get<std::string>();
    }
    else
    {
        // Targets the original input, not the live database, which is usually a
        // private copy in a temp dir. A database saves onto itself; a raw binary
        // saves as "<input>.i64".
        const std::string& in = g_original_input;
        outpath = in.empty() ? std::string(get_path(PATH_TYPE_IDB))
                : has_db_extension(in) ? in
                                       : in + ".i64";
    }

    // Written to a per-worker sibling then renamed over the target. Racing workers
    // resolve to last-writer-wins, and a half-written .i64 is never observable at
    // the final path. The sibling must share the directory for rename to be atomic.
    std::string uniq = g_db_dir.empty()
        ? std::string("tmp")
        : g_db_dir.substr(g_db_dir.find_last_of("/\\") + 1);
    std::string tmp = outpath + ".sav-" + uniq;

    // Kept for both the cheap writability probe and the failure message.
    size_t slash = outpath.find_last_of("/\\");
    std::string outdir = (slash == std::string::npos)
        ? std::string(".")
        : (slash == 0 ? std::string("/") : outpath.substr(0, slash));

    bool ok = save_database(tmp.c_str(), 0, nullptr, nullptr);
    std::string error;
    if (ok)
    {
        // POSIX rename replaces in place. Where it refuses to overwrite, the unlink
        // retry reopens a brief window in which the target does not exist.
        if (qrename(tmp.c_str(), outpath.c_str()) != 0)
        {
            qunlink(outpath.c_str());
            if (qrename(tmp.c_str(), outpath.c_str()) != 0)
            {
                qunlink(tmp.c_str());
                ok = false;
                error = "wrote database but could not move it into place at '"
                      + outpath + "' (directory '" + outdir
                      + "' may be read-only)";
            }
        }
    }
    else
    {
        qunlink(tmp.c_str());
        error = "save_database failed writing to '" + tmp
              + "': could not save to '" + outpath + "' (directory '"
              + outdir + "' may be read-only or full)";
    }

    // The hint only fires for the auto-derived default, where the caller had no
    // say in the destination.
    if (!ok && !params.contains("output_path"))
        error += " - pass 'output_path' to save to a writable directory";

    json result = {
        {"path", outpath},
        {"success", ok},
        {"func_count", get_func_qty()},
        {"seg_count", get_segm_qty()},
    };
    if (!ok)
        result["error"] = error;
    return result;
}

const command_entry_t kCommands[] = {
    { "get_info",      cmd_get_info },
    { "list_funcs",    cmd_list_funcs },
    { "list_segments", cmd_list_segments },
    { "lookup_func",   cmd_lookup_func },
    { "save_idb",      cmd_save_idb },
};

}  // namespace

void register_core_commands(CommandDispatcher &dispatcher)
{
    dispatcher.register_table(kCommands);
}

}  // namespace ida_hive
