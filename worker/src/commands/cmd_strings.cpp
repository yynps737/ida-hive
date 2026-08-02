#include "ida_hive/pch.hpp"

#include <ida.hpp>
#include <bytes.hpp>
#include <strlist.hpp>
#include <nalt.hpp>

#include "ida_hive/commands.hpp"
#include "ida_hive/util.hpp"
#include "ida_hive/params.hpp"

namespace ida_hive {
namespace {

// IDA 9.4 adds decompiler-recovered strings to the string list as entries of their
// own, typed STRTYPE_DECOMP. Such an entry has no bytes at its address: the text
// lives in string_info_ex_t::decompiler_string. The list is filled lazily, so these
// appear only for functions that have already been decompiled.

bool is_decompiler_string(const string_info_ex_t &si)
{
    return si.type == STRTYPE_DECOMP && !si.decompiler_string.empty();
}

const char *strtype_name(int type)
{
    if (type == STRTYPE_DECOMP)
        return "decompiler";
    switch (get_str_type_code(type))
    {
        case STRTYPE_C:      return "c";
        case STRTYPE_C_16:   return "utf16";
        case STRTYPE_C_32:   return "utf32";
        case STRTYPE_PASCAL: return "pascal";
        case STRTYPE_LEN2:   return "len2";
        case STRTYPE_LEN4:   return "len4";
        default:             return "other";
    }
}

// Reads an entry's text from whichever place holds it.
qstring string_text(const string_info_ex_t &si)
{
    if (is_decompiler_string(si))
        return si.decompiler_string;

    qstring raw;
    get_strlit_contents(&raw, si.ea, si.length, si.type);
    return raw;
}

// The string list is built on demand; an empty list usually means it was never
// requested rather than that the binary has no strings.
void ensure_strlist()
{
    if (get_strlist_qty() == 0)
        build_strlist();
}

// Every string with both its raw contents and the decompiler's rendering.
json cmd_strings(const json &params)
{
    const size_t limit     = opt_limit(params, 200);
    const size_t offset    = opt_size(params, "offset", 0);
    const size_t min_len   = opt_size(params, "min_length", 4);
    const std::string filt = opt_str(params, "filter");

    ensure_strlist();

    const size_t total = get_strlist_qty();
    json items = json::array();
    size_t scanned = 0;

    for (size_t i = 0; i < total && items.size() < limit; i++)
    {
        string_info_ex_t si;
        if (!get_strlist_item_ex(&si, i))
            continue;
        if ((size_t)si.length < min_len)
            continue;

        const qstring text = string_text(si);
        if (!filt.empty() && qstrstr(text.c_str(), filt.c_str()) == nullptr)
            continue;

        if (scanned++ < offset)
            continue;

        items.push_back({
            { "ea",            ea_hex(si.ea) },
            { "length",        si.length },
            { "type",          strtype_name(si.type) },
            { "text",          text.c_str() },
            // True for entries the decompiler recovered rather than ones present in
            // the binary's data; their address holds no such bytes.
            { "from_decompiler", is_decompiler_string(si) },
        });
    }

    return {
        { "total",    (uint64)total },
        { "returned", (int)items.size() },
        { "strings",  items },
    };
}

// Only the strings the decompiler reconstructed — ones assembled at runtime, or
// stored in a form the data listing cannot show. They exist nowhere in the binary's
// bytes, so no data scan finds them.
//
// The list is lazy: a function contributes only once it has been decompiled.
json cmd_strings_decompiled(const json &params)
{
    const size_t limit = opt_limit(params, 100);

    ensure_strlist();

    const size_t total = get_strlist_qty();
    json items = json::array();

    for (size_t i = 0; i < total && items.size() < limit; i++)
    {
        string_info_ex_t si;
        if (!get_strlist_item_ex(&si, i) || !is_decompiler_string(si))
            continue;

        items.push_back({
            { "ea",   ea_hex(si.ea) },
            { "text", si.decompiler_string.c_str() },
        });
    }

    return {
        { "count",   (int)items.size() },
        { "strings", items },
        { "note",    "populated lazily; decompile the functions of interest first" },
    };
}

// Forces a rebuild, which the caller needs after patching or defining new data.
json cmd_strings_rebuild(const json &)
{
    clear_strlist();
    build_strlist();
    return { { "count", (uint64)get_strlist_qty() } };
}

const command_entry_t kCommands[] = {
    { "strings",           cmd_strings           },
    { "strings_decompiled", cmd_strings_decompiled },
    { "strings_rebuild",   cmd_strings_rebuild   },
};

}  // namespace

void register_string_commands(CommandDispatcher &dispatcher)
{
    dispatcher.register_table(kCommands);
}

}  // namespace ida_hive
