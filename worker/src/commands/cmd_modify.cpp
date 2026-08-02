#include "ida_hive/pch.hpp"

#include <ida.hpp>
#include <name.hpp>
#include <funcs.hpp>
#include <lines.hpp>
#include <bytes.hpp>
#include <ua.hpp>

#include "ida_hive/commands.hpp"
#include "ida_hive/util.hpp"
#include "ida_hive/params.hpp"

namespace ida_hive {
namespace {

json cmd_rename(const json &params)
{
    ea_t ea = require_ea(params);
    std::string new_name = params.at("name").get<std::string>();

    bool ok = set_name(ea, new_name.c_str(), SN_CHECK);
    if (!ok)
        throw std::runtime_error("Failed to rename (name may be invalid or duplicate)");

    return {{"ea", ea_hex(ea)}, {"name", new_name}, {"success", true}};
}

json cmd_set_comment(const json &params)
{
    ea_t ea = require_ea(params);
    std::string comment = params.at("comment").get<std::string>();
    bool repeatable = params.value("repeatable", false);

    bool ok = set_cmt(ea, comment.c_str(), repeatable);
    if (!ok)
        throw std::runtime_error("Failed to set comment");

    return {{"ea", ea_hex(ea)}, {"success", true}};
}

json cmd_get_name(const json &params)
{
    ea_t ea = require_ea(params);

    qstring name;
    get_ea_name(&name, ea);

    return {{"ea", ea_hex(ea)}, {"name", name.c_str()}};
}

json cmd_append_comments(const json &params)
{
    ea_t ea = require_ea(params);
    std::string text = params.at("comment").get<std::string>();
    bool repeatable = params.value("repeatable", false);

    qstring existing;
    get_cmt(&existing, ea, repeatable);

    std::string merged = existing.c_str();
    if (!merged.empty())
        merged += " | ";
    merged += text;

    bool ok = set_cmt(ea, merged.c_str(), repeatable);
    return {{"ea", ea_hex(ea)}, {"success", ok}};
}

json cmd_define_func(const json &params)
{
    ea_t ea = require_ea(params);
    ea_t end = params.contains("end") ? parse_ea(params["end"]) : BADADDR;

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
}

json cmd_define_code(const json &params)
{
    ea_t ea = require_ea(params);

    insn_t insn;
    int len = create_insn(ea, &insn);
    if (len <= 0)
        throw std::runtime_error("Failed to create instruction");

    return {{"ea", ea_hex(ea)}, {"size", len}, {"success", true}};
}

json cmd_undefine(const json &params)
{
    ea_t ea = require_ea(params);
    asize_t size = params.value("size", 1);
    if (size == 0)
        size = get_item_size(ea);

    del_items(ea, DELIT_SIMPLE, size);
    return {{"ea", ea_hex(ea)}, {"size", size}, {"success", true}};
}

// No patch_asm yet. processor_t::assemble() exists and could back one; until
// then patch_bytes takes pre-assembled hex.

const command_entry_t kCommands[] = {
    { "rename",          cmd_rename },
    { "set_comment",     cmd_set_comment },
    { "get_name",        cmd_get_name },
    { "append_comments", cmd_append_comments },
    { "define_func",     cmd_define_func },
    { "define_code",     cmd_define_code },
    { "undefine",        cmd_undefine },
};

}  // namespace

void register_modify_commands(CommandDispatcher &dispatcher)
{
    dispatcher.register_table(kCommands);
}

}  // namespace ida_hive
