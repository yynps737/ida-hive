#include "ida_hive/pch.hpp"

#include <ida.hpp>
#include <idp.hpp>
#include <typeinf.hpp>
#include <name.hpp>
#include <funcs.hpp>
#include <bytes.hpp>
#include <hexrays.hpp>

#include "ida_hive/commands.hpp"
#include "ida_hive/util.hpp"
#include "ida_hive/params.hpp"

namespace ida_hive {
namespace {

json cmd_set_type(const json &params)
{
    ea_t ea = require_ea(params);
    std::string type_str = params.at("type").get<std::string>();

    // apply_cdecl needs the trailing ';' that the documented examples omit.
    std::string cdecl_str = type_str;
    size_t last = cdecl_str.find_last_not_of(" \t\r\n");
    if (last == std::string::npos || cdecl_str[last] != ';')
        cdecl_str += ';';

    bool ok = apply_cdecl(nullptr, ea, cdecl_str.c_str());

    if (!ok)
    {
        tinfo_t tif;
        if (parse_decl(&tif, nullptr, nullptr, type_str.c_str(), PT_SIL))
            ok = apply_tinfo(ea, tif, TINFO_DEFINITE);
    }

    if (!ok)
        throw std::runtime_error("Failed to apply type: " + type_str);

    tinfo_t result_tif;
    qstring applied;
    if (get_tinfo(&result_tif, ea))
        result_tif.print(&applied);

    return {{"ea", ea_hex(ea)}, {"type", applied.c_str()}, {"success", true}};
}

json cmd_type_inspect(const json &params)
{
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

    // get_size() yields BADSIZE for function types; null keeps the 0xFFFF...
    // sentinel out of the response.
    asize_t tsize = tif.get_size();
    json size_val = (tif.is_func() || tsize == BADSIZE) ? json(nullptr) : json((size_t)tsize);

    return {
        {"type",   type_str.c_str()},
        {"size",   size_val},
        {"is_ptr", tif.is_ptr()},
        {"is_func", tif.is_func()},
        {"is_struct", tif.is_struct()},
        {"is_enum", tif.is_enum()},
        {"is_array", tif.is_array()},
    };
}

json cmd_declare_type(const json &params)
{
    std::string decl = params.at("decl").get<std::string>();

    // parse_decls returns an error count, negative on hard failure — never a
    // count of parsed types.
    int count = parse_decls(nullptr, decl.c_str(), nullptr, HTI_DCL);
    if (count < 0)
        throw std::runtime_error("Failed to parse declaration");

    return {{"errors", count}, {"parsed", count == 0}, {"success", true}};
}

json cmd_type_query(const json &params)
{
    std::string filter = params.value("filter", std::string{});
    size_t limit = opt_limit(params, 50);

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
}

json cmd_search_structs(const json &params)
{
    std::string filter = params.value("filter", std::string{});
    size_t limit = opt_limit(params, 50);

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
}

json cmd_infer_types(const json &params)
{
    func_t &f = require_func(params);

    cfuncptr_t cfunc = require_decompiled(f);

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

    return {{"ea", ea_hex(f.start_ea)}, {"variables", vars}};
}

json cmd_enum_upsert(const json &params)
{
    std::string ename = params.at("name").get<std::string>();
    auto members = params.at("members");
    bool bitfield = params.value("bitfield", false);

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
}

json cmd_read_struct(const json &params)
{
    ea_t ea = require_ea(params);
    std::string sname = params.at("struct_name").get<std::string>();

    tinfo_t tif;
    if (!tif.get_named_type(nullptr, sname.c_str()))
        throw std::runtime_error("Struct not found: " + sname);

    if (!tif.is_struct() && !tif.is_union())
        throw std::runtime_error("Not a struct/union: " + sname);

    asize_t ssize = tif.get_size();
    if (ssize == 0 || ssize == BADSIZE)
        throw std::runtime_error("Cannot determine struct size");

    std::vector<uint8_t> data(ssize);
    get_bytes(data.data(), ssize, ea);

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
}

json cmd_type_apply_batch(const json &params)
{
    auto items = params.at("items");
    json results = json::array();
    int success_count = 0;

    for (auto& item : items)
    {
        ea_t ea = parse_ea(item.at("ea"));
        std::string type_str = item.at("type").get<std::string>();

        // Same sequence as set_type, including the ';' apply_cdecl requires.
        std::string cdecl_str = type_str;
        size_t last = cdecl_str.find_last_not_of(" \t\r\n");
        if (last == std::string::npos || cdecl_str[last] != ';')
            cdecl_str += ';';

        bool ok = apply_cdecl(nullptr, ea, cdecl_str.c_str());
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
}

const command_entry_t kCommands[] = {
    { "set_type",         cmd_set_type },
    { "type_inspect",     cmd_type_inspect },
    { "declare_type",     cmd_declare_type },
    { "type_query",       cmd_type_query },
    { "search_structs",   cmd_search_structs },
    { "infer_types",      cmd_infer_types },
    { "enum_upsert",      cmd_enum_upsert },
    { "read_struct",      cmd_read_struct },
    { "type_apply_batch", cmd_type_apply_batch },
};

}  // namespace

void register_type_commands(CommandDispatcher &dispatcher)
{
    dispatcher.register_table(kCommands);
}

}  // namespace ida_hive
