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

        ea_t ea = BADADDR;
        try { ea = (ea_t)std::stoull(target, nullptr, 0); } catch (...) {}

        if (ea == BADADDR || !get_func(ea))
            ea = get_name_ea(BADADDR, target.c_str());

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
    dispatcher.register_command("save_idb", [](const json& params) -> json {
        // get current database path
        const char* dbpath = get_path(PATH_TYPE_IDB);

        // save
        save_database(dbpath, 0, nullptr, nullptr);

        return {
            {"path", dbpath},
            {"success", true},
            {"func_count", get_func_qty()},
            {"seg_count", get_segm_qty()},
        };
    });
}
