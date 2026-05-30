// cmd_core.cpp - Core query commands
#include "../pch.h"

#include <ida.hpp>
#include <idp.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <auto.hpp>
#include <entry.hpp>
#include <loader.hpp>
#include <idalib.hpp>
#include <fpro.h>

#include "cmd_core.h"
#include "../util.h"

void register_core_commands(CommandDispatcher& dispatcher)
{
    // ---- get_info ----
    dispatcher.register_command("get_info", [](const json& params) -> json {
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
    });

    // ---- list_funcs ----
    // params: {offset?: int, limit?: int, filter?: string}
    dispatcher.register_command("list_funcs", [](const json& params) -> json {
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
    });

    // ---- list_segments ----
    dispatcher.register_command("list_segments", [](const json& params) -> json {
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
    });

    // ---- lookup_func ----
    // params: {target: string}  — address or name
    dispatcher.register_command("lookup_func", [](const json& params) -> json {
        std::string target = params.at("target").get<std::string>();

        // Numeric address first, then the shared name resolver (handles primary
        // names, demangled/short names, entry exports, and glibc-decorated
        // aliases like free -> __GI___libc_free). Same logic as parse_ea so
        // lookup_func and decompile-by-name stay consistent.
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
    });

    // ---- save_idb ----
    // Save current analysis as .i64 database
    // params: {output_path?: string}  — optional custom save path
    dispatcher.register_command("save_idb", [](const json& params) -> json {
        std::string outpath;
        if (params.contains("output_path") && !params["output_path"].is_null())
        {
            outpath = params["output_path"].get<std::string>();
        }
        else
        {
            // Default next to the ORIGINAL input, not the live database — the
            // live DB may be a private copy in a temp dir. An .i64/.idb input
            // saves back onto itself; a raw binary saves as "<input>.i64".
            const std::string& in = g_original_input;
            outpath = in.empty() ? std::string(get_path(PATH_TYPE_IDB))
                    : has_db_extension(in) ? in
                                           : in + ".i64";
        }

        // Save atomically: write to a per-worker temp sibling in the SAME
        // directory, then rename over the target. If two workers (e.g. separate
        // coordinator processes that opened the same binary) race to save the
        // same path, rename makes it last-writer-wins with no torn database — a
        // half-written .i64 is never observable at the final path.
        std::string uniq = g_db_dir.empty()
            ? std::string("tmp")
            : g_db_dir.substr(g_db_dir.find_last_of("/\\") + 1);
        std::string tmp = outpath + ".sav-" + uniq;

        // Derive the target directory so we can both detect a read-only
        // destination cheaply and report it precisely on failure.
        size_t slash = outpath.find_last_of("/\\");
        std::string outdir = (slash == std::string::npos)
            ? std::string(".")
            : (slash == 0 ? std::string("/") : outpath.substr(0, slash));

        bool ok = save_database(tmp.c_str(), 0, nullptr, nullptr);
        std::string error;
        if (ok)
        {
            // POSIX rename atomically replaces; where it won't overwrite, unlink
            // then retry (leaves a small non-atomic window on those platforms).
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

        // On any failure the destination directory is the usual culprit; when
        // this was the auto-derived default (no explicit output_path), advise
        // the caller to pass one pointing at a writable location.
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
    });
}
