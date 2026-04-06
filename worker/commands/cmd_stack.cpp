// cmd_stack.cpp - Stack frame commands (IDA 9.2 compatible using Hex-Rays lvars)
#include "../pch.h"

#include <ida.hpp>
#include <funcs.hpp>
#include <frame.hpp>
#include <typeinf.hpp>
#include <name.hpp>
#include <hexrays.hpp>

#include "cmd_stack.h"
#include "../util.h"

void register_stack_commands(CommandDispatcher& dispatcher)
{
    // ---- stack_frame ----
    // Get stack variables via Hex-Rays decompiler (most reliable in IDA 9.2)
    // params: {ea: string}
    dispatcher.register_command("stack_frame", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
        func_t* f = get_func(ea);
        if (!f)
            throw std::runtime_error("No function at address");

        if (!init_hexrays_plugin())
            throw std::runtime_error("Hex-Rays required for stack frame analysis");

        hexrays_failure_t hf;
        cfuncptr_t cfunc = decompile(f, &hf);
        if (!cfunc)
            throw std::runtime_error("Decompilation failed");

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
        get_func_name(&func_name, f->start_ea);

        return {
            {"ea",         ea_hex(f->start_ea)},
            {"name",       func_name.c_str()},
            {"frame_size", (size_t)f->frsize},
            {"variables",  vars},
        };
    });

    // ---- declare_stack ----
    // Rename/retype a stack variable via Hex-Rays lvar
    // params: {ea: string, old_name: string, new_name?: string, type?: string}
    dispatcher.register_command("declare_stack", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
        std::string old_name = params.at("old_name").get<std::string>();
        std::string new_name = params.value("new_name", std::string{});
        std::string type_str = params.value("type", std::string{});

        func_t* f = get_func(ea);
        if (!f) throw std::runtime_error("No function at address");
        if (!init_hexrays_plugin()) throw std::runtime_error("Hex-Rays required");

        hexrays_failure_t hf;
        cfuncptr_t cfunc = decompile(f, &hf);
        if (!cfunc) throw std::runtime_error("Decompilation failed");

        lvars_t* lvars = cfunc->get_lvars();
        if (!lvars) throw std::runtime_error("No local variables");

        // Find the variable
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

        // Rename
        if (!new_name.empty())
        {
            renamed = rename_lvar(f->start_ea, old_name.c_str(), new_name.c_str());
        }

        // Retype
        if (!type_str.empty())
        {
            tinfo_t tif;
            if (parse_decl(&tif, nullptr, nullptr, type_str.c_str(), PT_SIL))
            {
                lvar_saved_info_t lsi;
                lsi.ll.location = target->location;
                lsi.ll.defea = target->defea;
                lsi.type = tif;
                lsi.name = new_name.empty() ? old_name.c_str() : new_name.c_str();
                lsi.size = tif.get_size();
                retyped = modify_user_lvar_info(f->start_ea, MLI_TYPE, lsi);
            }
        }

        return {
            {"ea", ea_hex(f->start_ea)},
            {"old_name", old_name},
            {"renamed", renamed},
            {"retyped", retyped},
            {"success", renamed || retyped},
        };
    });

    // ---- delete_stack ----
    // Reset a stack variable name back to IDA default
    // params: {ea: string, name: string}
    dispatcher.register_command("delete_stack", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
        std::string vname = params.at("name").get<std::string>();

        func_t* f = get_func(ea);
        if (!f) throw std::runtime_error("No function at address");
        if (!init_hexrays_plugin()) throw std::runtime_error("Hex-Rays required");

        // Reset name by renaming to empty string (IDA will use default name)
        bool ok = rename_lvar(f->start_ea, vname.c_str(), "");

        return {{"ea", ea_hex(f->start_ea)}, {"name", vname}, {"reset", ok}};
    });
}
