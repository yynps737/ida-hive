// cmd_modify.cpp - Modification commands: rename, set_comment
#include "../pch.h"

#include <ida.hpp>
#include <name.hpp>
#include <funcs.hpp>
#include <lines.hpp>
#include <bytes.hpp>
#include <ua.hpp>

#include "cmd_modify.h"
#include "../util.h"

void register_modify_commands(CommandDispatcher& dispatcher)
{
    // ---- rename ----
    dispatcher.register_command("rename", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
        std::string new_name = params.at("name").get<std::string>();

        bool ok = set_name(ea, new_name.c_str(), SN_CHECK);
        if (!ok)
            throw std::runtime_error("Failed to rename (name may be invalid or duplicate)");

        return {{"ea", ea_hex(ea)}, {"name", new_name}, {"success", true}};
    });

    // ---- set_comment ----
    dispatcher.register_command("set_comment", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
        std::string comment = params.at("comment").get<std::string>();
        bool repeatable = params.value("repeatable", false);

        bool ok = set_cmt(ea, comment.c_str(), repeatable);
        if (!ok)
            throw std::runtime_error("Failed to set comment");

        return {{"ea", ea_hex(ea)}, {"success", true}};
    });

    // ---- get_name ----
    dispatcher.register_command("get_name", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));

        qstring name;
        get_ea_name(&name, ea);

        return {{"ea", ea_hex(ea)}, {"name", name.c_str()}};
    });

    // ---- append_comments ----
    // Append text to existing comment
    // params: {ea: string, comment: string, repeatable?: bool}
    dispatcher.register_command("append_comments", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
        std::string text = params.at("comment").get<std::string>();
        bool repeatable = params.value("repeatable", false);

        qstring existing;
        get_cmt(&existing, ea, repeatable);

        std::string merged = existing.c_str();
        if (!merged.empty() && merged.back() != '\n')
            merged += "\n";
        merged += text;

        set_cmt(ea, merged.c_str(), repeatable);
        return {{"ea", ea_hex(ea)}, {"success", true}};
    });

    // ---- define_func ----
    // Define a function at address
    // params: {ea: string, end?: string}
    dispatcher.register_command("define_func", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
        ea_t end = params.contains("end") ? parse_ea(params["end"]) : BADADDR;

        // Check if function already exists
        func_t* existing = get_func(ea);
        if (existing && existing->start_ea == ea)
        {
            qstring name;
            get_func_name(&name, ea);
            return {
                {"ea", ea_hex(ea)}, {"end", ea_hex(existing->end_ea)},
                {"name", name.c_str()}, {"already_exists", true}, {"success", true},
            };
        }

        bool ok = add_func(ea, end);
        if (!ok)
            throw std::runtime_error("Failed to define function at " + ea_hex(ea));

        func_t* f = get_func(ea);
        qstring name;
        if (f) get_func_name(&name, f->start_ea);

        return {
            {"ea", ea_hex(ea)},
            {"end", f ? ea_hex(f->end_ea) : ""},
            {"name", f ? name.c_str() : ""},
            {"already_exists", false},
            {"success", true},
        };
    });

    // ---- define_code ----
    // Convert bytes to code
    // params: {ea: string}
    dispatcher.register_command("define_code", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));

        insn_t insn;
        int len = create_insn(ea, &insn);
        if (len <= 0)
            throw std::runtime_error("Failed to create instruction");

        return {{"ea", ea_hex(ea)}, {"size", len}, {"success", true}};
    });

    // ---- undefine ----
    // Undefine items (convert back to raw bytes)
    // params: {ea: string, size?: int}
    dispatcher.register_command("undefine", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
        asize_t size = params.value("size", 1);

        del_items(ea, DELIT_SIMPLE, size);
        return {{"ea", ea_hex(ea)}, {"size", size}, {"success", true}};
    });

    // patch_asm not available in C++ idalib — IDA 9.2 has no public C assemble() API.
    // Use patch_bytes with pre-assembled hex instead.
}
