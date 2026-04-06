// cmd_search.cpp - Search commands: find_regex, find_bytes, imports, func_query, entity_query
#include "../pch.h"

#include <ida.hpp>
#include <idp.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <nalt.hpp>
#include <strlist.hpp>
#include <search.hpp>

#include "cmd_search.h"
#include "../util.h"

#include <regex>
#include <set>

void register_search_commands(CommandDispatcher& dispatcher)
{
    // ---- find_regex ----
    // Search strings by regex pattern
    // params: {pattern: string, limit?: int}
    dispatcher.register_command("find_regex", [](const json& params) -> json {
        std::string pattern_str = params.at("pattern").get<std::string>();
        size_t limit = params.value("limit", 30);

        std::regex re(pattern_str, std::regex_constants::icase);

        json matches = json::array();
        string_info_t si;
        for (size_t i = 0; get_strlist_item(&si, i) && matches.size() < limit; i++)
        {
            qstring str;
            get_strlit_contents(&str, si.ea, si.length, si.type);
            std::string s(str.c_str());

            if (std::regex_search(s, re))
            {
                matches.push_back({
                    {"ea",     ea_hex(si.ea)},
                    {"string", s},
                    {"length", si.length},
                });
            }
        }

        return {{"matches", matches}, {"count", matches.size()}};
    });

    // ---- find_bytes ----
    // Search byte patterns with ?? wildcards
    // params: {hex: string, start?: string, limit?: int}
    dispatcher.register_command("find_bytes", [](const json& params) -> json {
        std::string hex = params.at("hex").get<std::string>();
        size_t limit = params.value("limit", 10);

        ea_t start = params.contains("start") ? parse_ea(params["start"]) : inf_get_min_ea();
        ea_t end = inf_get_max_ea();

        // Parse hex + wildcards into compiled_binpat_vec_t
        compiled_binpat_vec_t binpat;
        qstring errbuf;
        parse_binpat_str(&binpat, start, hex.c_str(), 16, PBSENC_DEF1BPU, &errbuf);

        if (binpat.empty())
            throw std::runtime_error("Invalid byte pattern: " + std::string(errbuf.c_str()));

        json results = json::array();
        ea_t addr = start;
        for (size_t i = 0; i < limit; i++)
        {
            addr = bin_search(addr, end, binpat, BIN_SEARCH_FORWARD);
            if (addr == BADADDR) break;

            results.push_back({{"ea", ea_hex(addr)}});
            addr += 1; // advance past match
        }

        return {{"matches", results}, {"count", results.size()}};
    });

    // ---- imports ----
    // List all imports
    // params: {limit?: int, filter?: string}
    dispatcher.register_command("imports", [](const json& params) -> json {
        size_t limit = params.value("limit", 500);
        std::string filter = params.value("filter", std::string{});

        json imports = json::array();

        int mod_count = get_import_module_qty();
        for (int i = 0; i < mod_count && imports.size() < limit; i++)
        {
            qstring mod_name;
            get_import_module_name(&mod_name, i);

            struct ImportCtx {
                json* imports;
                const char* mod_name;
                size_t limit;
                std::string filter;
            };

            ImportCtx ctx = { &imports, mod_name.c_str(), limit, filter };

            enum_import_names(i, [](ea_t ea, const char* name, uval_t ord, void* param) -> int {
                auto* ctx = (ImportCtx*)param;
                if (ctx->imports->size() >= ctx->limit) return 0; // stop

                std::string n = name ? name : "";
                if (!ctx->filter.empty() && n.find(ctx->filter) == std::string::npos)
                    return 1; // continue

                ctx->imports->push_back({
                    {"ea",      ea_hex(ea)},
                    {"name",    n},
                    {"ordinal", ord},
                    {"module",  ctx->mod_name},
                });
                return 1; // continue
            }, &ctx);
        }

        return {{"imports", imports}, {"count", imports.size()}, {"modules", mod_count}};
    });

    // ---- func_query ----
    // Advanced function search with size/name/type filters
    // params: {filter?, min_size?, max_size?, limit?, offset?}
    dispatcher.register_command("func_query", [](const json& params) -> json {
        std::string filter = params.value("filter", std::string{});
        size_t min_size = params.value("min_size", 0);
        size_t max_size = params.value("max_size", (size_t)0xFFFFFFFF);
        size_t limit = params.value("limit", 100);
        size_t offset = params.value("offset", 0);

        json funcs = json::array();
        size_t total = get_func_qty();
        size_t matched = 0;
        size_t skipped = 0;

        for (size_t i = 0; i < total && funcs.size() < limit; i++)
        {
            func_t* f = getn_func(i);
            if (!f) continue;

            size_t fsize = (size_t)(f->end_ea - f->start_ea);
            if (fsize < min_size || fsize > max_size) continue;

            qstring name;
            get_func_name(&name, f->start_ea);

            if (!filter.empty() && std::string(name.c_str()).find(filter) == std::string::npos)
                continue;

            matched++;
            if (skipped < offset) { skipped++; continue; }

            funcs.push_back({
                {"ea",   ea_hex(f->start_ea)},
                {"name", name.c_str()},
                {"size", fsize},
            });
        }

        return {{"functions", funcs}, {"total", total}, {"matched", matched}};
    });

    // ---- list_globals ----
    // List named addresses (non-function)
    // params: {filter?, limit?, offset?}
    dispatcher.register_command("list_globals", [](const json& params) -> json {
        std::string filter = params.value("filter", std::string{});
        size_t limit = params.value("limit", 100);
        size_t offset = params.value("offset", 0);

        json globals = json::array();
        size_t matched = 0;
        size_t skipped = 0;

        size_t qty = get_nlist_size();
        for (size_t i = 0; i < qty && globals.size() < limit; i++)
        {
            ea_t ea = get_nlist_ea(i);
            if (get_func(ea)) continue; // skip functions

            const char* name = get_nlist_name(i);
            if (!name) continue;

            if (!filter.empty() && std::string(name).find(filter) == std::string::npos)
                continue;

            matched++;
            if (skipped < offset) { skipped++; continue; }

            globals.push_back({
                {"ea",   ea_hex(ea)},
                {"name", name},
            });
        }

        return {{"globals", globals}, {"matched", matched}};
    });

    // ---- int_convert ----
    // Number base conversion utility
    // params: {value: string}
    dispatcher.register_command("int_convert", [](const json& params) -> json {
        std::string val_str = params.at("value").get<std::string>();
        uint64_t val = std::stoull(val_str, nullptr, 0);

        char hex_buf[32], dec_buf[32], oct_buf[32];
        qsnprintf(hex_buf, sizeof(hex_buf), "0x%llX", (unsigned long long)val);
        qsnprintf(dec_buf, sizeof(dec_buf), "%llu", (unsigned long long)val);
        qsnprintf(oct_buf, sizeof(oct_buf), "0%llo", (unsigned long long)val);

        // Binary
        std::string bin = "0b";
        if (val == 0) { bin += "0"; }
        else {
            bool started = false;
            for (int bit = 63; bit >= 0; bit--) {
                if (val & (1ULL << bit)) { bin += '1'; started = true; }
                else if (started) { bin += '0'; }
            }
        }

        return {
            {"hex", hex_buf},
            {"dec", dec_buf},
            {"oct", oct_buf},
            {"bin", bin},
            {"signed", (int64_t)val},
        };
    });

    // ---- imports_query ----
    // Filtered imports with module and pagination
    // params: {filter?: string, module?: string, offset?: int, limit?: int}
    dispatcher.register_command("imports_query", [](const json& params) -> json {
        std::string filter = params.value("filter", std::string{});
        std::string mod_filter = params.value("module", std::string{});
        size_t offset = params.value("offset", 0);
        size_t limit = params.value("limit", 100);

        json imports = json::array();
        size_t matched = 0, skipped = 0;

        int mod_count = get_import_module_qty();
        for (int i = 0; i < mod_count && imports.size() < limit; i++)
        {
            qstring mod_name;
            get_import_module_name(&mod_name, i);

            if (!mod_filter.empty() &&
                std::string(mod_name.c_str()).find(mod_filter) == std::string::npos)
                continue;

            struct Ctx {
                json* imports; const char* mod; size_t limit;
                std::string filter; size_t* matched; size_t* skipped; size_t offset;
            };
            Ctx ctx = {&imports, mod_name.c_str(), limit, filter, &matched, &skipped, offset};

            enum_import_names(i, [](ea_t ea, const char* name, uval_t ord, void* p) -> int {
                auto* c = (Ctx*)p;
                if (c->imports->size() >= c->limit) return 0;
                std::string n = name ? name : "";
                if (!c->filter.empty() && n.find(c->filter) == std::string::npos) return 1;
                (*c->matched)++;
                if (*c->skipped < c->offset) { (*c->skipped)++; return 1; }
                c->imports->push_back({
                    {"ea", ea_hex(ea)}, {"name", n}, {"ordinal", ord}, {"module", c->mod},
                });
                return 1;
            }, &ctx);
        }

        return {{"imports", imports}, {"matched", matched}, {"count", imports.size()}};
    });

    // ---- entity_query ----
    // Generic entity search across functions, globals, strings, imports
    // params: {kind: "functions"|"globals"|"strings"|"imports", filter?: string, limit?: int}
    dispatcher.register_command("entity_query", [](const json& params) -> json {
        std::string kind = params.at("kind").get<std::string>();
        std::string filter = params.value("filter", std::string{});
        size_t limit = params.value("limit", 100);

        json entities = json::array();

        if (kind == "functions")
        {
            size_t total = get_func_qty();
            for (size_t i = 0; i < total && entities.size() < limit; i++)
            {
                func_t* f = getn_func(i);
                if (!f) continue;
                qstring name;
                get_func_name(&name, f->start_ea);
                if (!filter.empty() && std::string(name.c_str()).find(filter) == std::string::npos) continue;
                entities.push_back({{"ea", ea_hex(f->start_ea)}, {"name", name.c_str()},
                    {"size", (size_t)(f->end_ea - f->start_ea)}, {"kind", "function"}});
            }
        }
        else if (kind == "globals")
        {
            size_t qty = get_nlist_size();
            for (size_t i = 0; i < qty && entities.size() < limit; i++)
            {
                ea_t ea = get_nlist_ea(i);
                if (get_func(ea)) continue;
                const char* name = get_nlist_name(i);
                if (!name) continue;
                if (!filter.empty() && std::string(name).find(filter) == std::string::npos) continue;
                entities.push_back({{"ea", ea_hex(ea)}, {"name", name}, {"kind", "global"}});
            }
        }
        else if (kind == "strings")
        {
            string_info_t si;
            for (size_t i = 0; get_strlist_item(&si, i) && entities.size() < limit; i++)
            {
                qstring str;
                get_strlit_contents(&str, si.ea, si.length, si.type);
                std::string s(str.c_str());
                if (!filter.empty() && s.find(filter) == std::string::npos) continue;
                entities.push_back({{"ea", ea_hex(si.ea)}, {"string", s},
                    {"length", si.length}, {"kind", "string"}});
            }
        }
        else if (kind == "imports")
        {
            int mod_count = get_import_module_qty();
            for (int i = 0; i < mod_count && entities.size() < limit; i++)
            {
                qstring mod_name;
                get_import_module_name(&mod_name, i);
                struct Ctx { json* e; size_t limit; std::string filter; const char* mod; };
                Ctx ctx = {&entities, limit, filter, mod_name.c_str()};
                enum_import_names(i, [](ea_t ea, const char* name, uval_t ord, void* p) -> int {
                    auto* c = (Ctx*)p;
                    if (c->e->size() >= c->limit) return 0;
                    std::string n = name ? name : "";
                    if (!c->filter.empty() && n.find(c->filter) == std::string::npos) return 1;
                    c->e->push_back({{"ea", ea_hex(ea)}, {"name", n},
                        {"module", c->mod}, {"kind", "import"}});
                    return 1;
                }, &ctx);
            }
        }
        else
        {
            throw std::runtime_error("Unknown kind: " + kind + " (use: functions/globals/strings/imports)");
        }

        return {{"entities", entities}, {"kind", kind}, {"count", entities.size()}};
    });
}
