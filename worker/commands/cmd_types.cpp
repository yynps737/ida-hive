// cmd_types.cpp - Type system commands
#include "../pch.h"

#include <ida.hpp>
#include <idp.hpp>
#include <typeinf.hpp>
#include <name.hpp>
#include <funcs.hpp>
#include <bytes.hpp>
#include <hexrays.hpp>

#include "cmd_types.h"
#include "../util.h"

void register_type_commands(CommandDispatcher& dispatcher)
{
    // ---- set_type ----
    // Apply a type string to an address
    // params: {ea: string, type: string}
    dispatcher.register_command("set_type", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
        std::string type_str = params.at("type").get<std::string>();

        // Try apply_cdecl first (handles "int __fastcall func(int a1, int a2)")
        bool ok = apply_cdecl(nullptr, ea, type_str.c_str());

        if (!ok)
        {
            // Fallback: parse as pure type and apply
            tinfo_t tif;
            if (parse_decl(&tif, nullptr, nullptr, type_str.c_str(), PT_SIL))
                ok = apply_tinfo(ea, tif, TINFO_DEFINITE);
        }

        if (!ok)
            throw std::runtime_error("Failed to apply type: " + type_str);

        // Read back
        tinfo_t result_tif;
        qstring applied;
        if (get_tinfo(&result_tif, ea))
            result_tif.print(&applied);

        return {{"ea", ea_hex(ea)}, {"type", applied.c_str()}, {"success", true}};
    });

    // ---- type_inspect ----
    // Get type info at an address or by type name
    // params: {ea?: string, name?: string}
    dispatcher.register_command("type_inspect", [](const json& params) -> json {
        tinfo_t tif;

        if (params.contains("ea"))
        {
            ea_t ea = parse_ea(params["ea"]);
            if (!get_tinfo(&tif, ea))
                throw std::runtime_error("No type at address");
        }
        else if (params.contains("name"))
        {
            std::string name = params["name"].get<std::string>();
            if (!tif.get_named_type(nullptr, name.c_str()))
                throw std::runtime_error("Type not found: " + name);
        }
        else
        {
            throw std::runtime_error("Must specify 'ea' or 'name'");
        }

        qstring type_str;
        tif.print(&type_str);

        return {
            {"type",   type_str.c_str()},
            {"size",   (size_t)tif.get_size()},
            {"is_ptr", tif.is_ptr()},
            {"is_func", tif.is_func()},
            {"is_struct", tif.is_struct()},
            {"is_enum", tif.is_enum()},
            {"is_array", tif.is_array()},
        };
    });

    // ---- declare_type ----
    // Parse and add C type declarations to local type library
    // params: {decl: string}
    dispatcher.register_command("declare_type", [](const json& params) -> json {
        std::string decl = params.at("decl").get<std::string>();

        int count = parse_decls(nullptr, decl.c_str(), nullptr, HTI_DCL);
        if (count < 0)
            throw std::runtime_error("Failed to parse declaration");

        return {{"parsed", count}, {"success", true}};
    });

    // ---- type_query ----
    // Search local types by name pattern
    // params: {filter?: string, limit?: int}
    dispatcher.register_command("type_query", [](const json& params) -> json {
        std::string filter = params.value("filter", std::string{});
        size_t limit = params.value("limit", 50);

        json types = json::array();
        til_t* ti = get_idati();
        if (!ti) return {{"types", types}};

        uint32_t count = get_ordinal_count(ti);
        for (uint32_t ord = 1; ord <= count && types.size() < limit; ord++)
        {
            const char* name = get_numbered_type_name(ti, ord);
            if (!name) continue;

            if (!filter.empty() && std::string(name).find(filter) == std::string::npos)
                continue;

            tinfo_t tif;
            if (tif.get_numbered_type(ti, ord))
            {
                qstring type_str;
                tif.print(&type_str);

                types.push_back({
                    {"ordinal", ord},
                    {"name",    name},
                    {"type",    type_str.c_str()},
                    {"size",    (size_t)tif.get_size()},
                });
            }
        }

        return {{"types", types}, {"total", count}};
    });

    // ---- search_structs ----
    // Search struct/union types
    // params: {filter?: string, limit?: int}
    dispatcher.register_command("search_structs", [](const json& params) -> json {
        std::string filter = params.value("filter", std::string{});
        size_t limit = params.value("limit", 50);

        json structs = json::array();
        til_t* ti = get_idati();
        if (!ti) return {{"structs", structs}};

        uint32_t count = get_ordinal_count(ti);
        for (uint32_t ord = 1; ord <= count && structs.size() < limit; ord++)
        {
            const char* name = get_numbered_type_name(ti, ord);
            if (!name) continue;

            tinfo_t tif;
            if (!tif.get_numbered_type(ti, ord)) continue;
            if (!tif.is_struct() && !tif.is_union()) continue;

            if (!filter.empty() && std::string(name).find(filter) == std::string::npos)
                continue;

            qstring type_str;
            tif.print(&type_str);

            structs.push_back({
                {"name", name},
                {"type", type_str.c_str()},
                {"size", (size_t)tif.get_size()},
                {"is_union", tif.is_union()},
            });
        }

        return {{"structs", structs}};
    });

    // ---- infer_types ----
    // Use Hex-Rays to infer types at an address
    // params: {ea: string}
    dispatcher.register_command("infer_types", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
        func_t* f = get_func(ea);
        if (!f)
            throw std::runtime_error("No function at address");

        if (!init_hexrays_plugin())
            throw std::runtime_error("Hex-Rays not available");

        hexrays_failure_t hf;
        cfuncptr_t cfunc = decompile(f, &hf);
        if (!cfunc)
            throw std::runtime_error("Decompilation failed");

        // Extract local variable types
        json vars = json::array();
        lvars_t* lvars = cfunc->get_lvars();
        if (lvars)
        {
            for (size_t i = 0; i < lvars->size(); i++)
            {
                lvar_t& lv = (*lvars)[i];
                qstring type_str;
                lv.type().print(&type_str);

                vars.push_back({
                    {"name",    lv.name.c_str()},
                    {"type",    type_str.c_str()},
                    {"is_arg",  lv.is_arg_var()},
                });
            }
        }

        return {{"ea", ea_hex(f->start_ea)}, {"variables", vars}};
    });

    // ---- enum_upsert ----
    // Create or extend an enum type
    // params: {name: string, members: [{name: string, value: int}], bitfield?: bool}
    dispatcher.register_command("enum_upsert", [](const json& params) -> json {
        std::string ename = params.at("name").get<std::string>();
        auto members = params.at("members");
        bool bitfield = params.value("bitfield", false);

        // Build C declaration for the enum
        std::string decl = "enum " + ename + " { ";
        for (size_t i = 0; i < members.size(); i++)
        {
            std::string mname = members[i].at("name").get<std::string>();
            int64_t mval = members[i].at("value").get<int64_t>();
            if (i > 0) decl += ", ";
            char buf[64];
            qsnprintf(buf, sizeof(buf), "%s = %lld", mname.c_str(), (long long)mval);
            decl += buf;
        }
        decl += " };";

        int count = parse_decls(nullptr, decl.c_str(), nullptr, HTI_DCL);
        if (count < 0)
            throw std::runtime_error("Failed to create enum: " + ename);

        return {{"name", ename}, {"members", members.size()}, {"success", true}};
    });

    // ---- read_struct ----
    // Read struct fields from memory at a given address
    // params: {ea: string, struct_name: string}
    dispatcher.register_command("read_struct", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
        std::string sname = params.at("struct_name").get<std::string>();

        tinfo_t tif;
        if (!tif.get_named_type(nullptr, sname.c_str()))
            throw std::runtime_error("Struct not found: " + sname);

        if (!tif.is_struct() && !tif.is_union())
            throw std::runtime_error("Not a struct/union: " + sname);

        asize_t ssize = tif.get_size();
        if (ssize == 0 || ssize == BADSIZE)
            throw std::runtime_error("Cannot determine struct size");

        // Read raw bytes
        std::vector<uint8_t> data(ssize);
        get_bytes(data.data(), ssize, ea);

        // Get member info via udt
        udt_type_data_t udt;
        if (!tif.get_udt_details(&udt))
            throw std::runtime_error("Cannot get struct details");

        json fields = json::array();
        for (size_t i = 0; i < udt.size(); i++)
        {
            udm_t& m = udt[i];
            qstring mname = m.name;

            qstring mtype;
            m.type.print(&mtype);

            asize_t moff = m.offset / 8; // bits to bytes
            asize_t msize = m.size / 8;

            // Read value as hex
            std::string hex_val;
            for (asize_t b = 0; b < msize && (moff + b) < ssize; b++)
            {
                char h[4];
                qsnprintf(h, sizeof(h), "%02X", data[moff + b]);
                hex_val += h;
            }

            fields.push_back({
                {"name",   mname.c_str()},
                {"type",   mtype.c_str()},
                {"offset", moff},
                {"size",   msize},
                {"hex",    hex_val},
            });
        }

        return {{"ea", ea_hex(ea)}, {"struct", sname}, {"size", ssize}, {"fields", fields}};
    });

    // ---- type_apply_batch ----
    // Apply types to multiple addresses in one call
    // params: {items: [{ea: string, type: string}]}
    dispatcher.register_command("type_apply_batch", [](const json& params) -> json {
        auto items = params.at("items");
        json results = json::array();
        int success_count = 0;

        for (auto& item : items)
        {
            ea_t ea = parse_ea(item.at("ea"));
            std::string type_str = item.at("type").get<std::string>();

            // Try apply_cdecl first (handles full C declarations with names)
            bool ok = apply_cdecl(nullptr, ea, type_str.c_str());
            if (!ok)
            {
                tinfo_t tif;
                if (parse_decl(&tif, nullptr, nullptr, type_str.c_str(), PT_SIL))
                    ok = apply_tinfo(ea, tif, TINFO_DEFINITE);
            }

            if (ok) success_count++;

            qstring applied;
            if (ok)
            {
                tinfo_t result_tif;
                if (get_tinfo(&result_tif, ea))
                    result_tif.print(&applied);
            }

            results.push_back({
                {"ea", ea_hex(ea)},
                {"success", ok},
                {"type", ok ? applied.c_str() : type_str.c_str()},
            });
        }

        return {{"results", results}, {"success_count", success_count}, {"total", items.size()}};
    });
}
