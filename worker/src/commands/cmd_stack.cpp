#include "ida_hive/pch.hpp"

#include <ida.hpp>
#include <funcs.hpp>
#include <frame.hpp>
#include <typeinf.hpp>
#include <name.hpp>
#include <hexrays.hpp>

#include "ida_hive/commands.hpp"
#include "ida_hive/util.hpp"
#include "ida_hive/params.hpp"

namespace ida_hive {
namespace {

// Read through Hex-Rays lvars; the frame API does not expose these.

json cmd_stack_frame(const json &params)
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
                {"name",     lv.name.c_str()},
                {"type",     type_str.c_str()},
                {"is_arg",   lv.is_arg_var()},
                {"is_stack", lv.is_stk_var()},
                {"width",    (size_t)lv.width},
            });
        }
    }

    qstring func_name;
    get_func_name(&func_name, f.start_ea);

    return {
        {"ea",         ea_hex(f.start_ea)},
        {"name",       func_name.c_str()},
        {"frame_size", (size_t)f.frsize},
        {"variables",  vars},
    };
}

json cmd_declare_stack(const json &params)
{
    std::string old_name = params.at("old_name").get<std::string>();
    std::string new_name = params.value("new_name", std::string{});
    std::string type_str = params.value("type", std::string{});

    func_t &f = require_func(params);
    cfuncptr_t cfunc = require_decompiled(f);

    lvars_t* lvars = cfunc->get_lvars();
    if (!lvars) throw std::runtime_error("No local variables");

    lvar_t* target = nullptr;
    for (size_t i = 0; i < lvars->size(); i++)
    {
        if ((*lvars)[i].name == old_name.c_str())
        {
            target = &(*lvars)[i];
            break;
        }
    }

    if (!target)
        throw std::runtime_error("Variable not found: " + old_name);

    bool renamed = false, retyped = false;
    bool want_rename = !new_name.empty();
    bool want_retype = !type_str.empty();
    std::string error;

    // Parsed before any rename commits, so an invalid type leaves nothing behind.
    // parse_decl() rejects a bare type like "char *"; it wants a terminated
    // declaration, hence PT_SEMICOLON and then the named-declaration retry.
    tinfo_t tif;
    bool type_ok = false;
    if (want_retype)
    {
        type_ok = parse_decl(
            &tif, nullptr, nullptr, type_str.c_str(), PT_SIL | PT_SEMICOLON);
        if (!type_ok)
        {
            std::string named_decl = type_str + " __hive_tmp_decl;";
            type_ok = parse_decl(
                &tif, nullptr, nullptr, named_decl.c_str(),
                PT_SIL | PT_SEMICOLON);
        }
        if (!type_ok && error.empty())
            error = "type parse failed";
    }

    // Skipped when a requested retype failed to parse, keeping the pair atomic.
    if (want_rename && (!want_retype || type_ok))
    {
        renamed = rename_lvar(f.start_ea, old_name.c_str(), new_name.c_str());
        if (!renamed && error.empty())
            error = "rename_lvar failed";
    }

    if (want_retype && type_ok)
    {
        const char* cur_name = (want_rename && renamed)
                             ? new_name.c_str()
                             : old_name.c_str();

        // locate_lvar() yields the locator the persistence layer matches on.
        // A raw lvar_t::location/defea does not match and the retype is dropped.
        lvar_saved_info_t lsi;
        if (!locate_lvar(&lsi.ll, f.start_ea, cur_name))
        {
            if (error.empty())
                error = "locate_lvar failed";
        }
        else
        {
            lsi.name = cur_name;
            lsi.type = tif;
            lsi.size = tif.get_size();
            // Name and type go together, or the stored entry drifts from the lvar.
            retyped = modify_user_lvar_info(
                f.start_ea, MLI_NAME | MLI_TYPE, lsi);
            if (!retyped && error.empty())
                error = "modify_user_lvar_info failed";
        }
    }

    // True only if every requested operation applied, never on a partial result.
    bool success = (!want_rename || renamed) && (!want_retype || retyped);

    json result = {
        {"ea", ea_hex(f.start_ea)},
        {"old_name", old_name},
        {"renamed", renamed},
        {"retyped", retyped},
        {"success", success},
    };
    if (!success && !error.empty())
        result["error"] = error;
    return result;
}

json cmd_delete_stack(const json &params)
{
    std::string vname = params.at("name").get<std::string>();

    func_t &f = require_func(params);
    if (!init_hexrays_plugin())
        throw std::runtime_error("Hex-Rays decompiler is not available");

    // An empty name restores IDA's generated default.
    bool ok = rename_lvar(f.start_ea, vname.c_str(), "");

    return {{"ea", ea_hex(f.start_ea)}, {"name", vname}, {"reset", ok}};
}

const command_entry_t kCommands[] = {
    { "stack_frame",   cmd_stack_frame },
    { "declare_stack", cmd_declare_stack },
    { "delete_stack",  cmd_delete_stack },
};

}  // namespace

void register_stack_commands(CommandDispatcher &dispatcher)
{
    dispatcher.register_table(kCommands);
}

}  // namespace ida_hive
