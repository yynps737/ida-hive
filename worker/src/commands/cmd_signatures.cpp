#include "ida_hive/pch.hpp"

#include <ida.hpp>
#include <funcs.hpp>
#include <name.hpp>

#include "ida_hive/commands.hpp"
#include "ida_hive/util.hpp"
#include "ida_hive/params.hpp"

namespace ida_hive {
namespace {

// FLIRT signatures let IDA recognise statically linked library code. Separating it
// from the program's own functions is the single largest noise reduction available
// on a stripped binary: a build with a static libc can carry thousands of matched
// functions that are of no interest to the reverser.

struct func_flag_name_t
{
    uint64      flag;
    const char *name;
};

// The flags that say something about a function's origin or shape.
const func_flag_name_t kFuncFlags[] = {
    { FUNC_NORET,     "noret"     },
    { FUNC_FAR,       "far"       },
    { FUNC_LIB,       "library"   },
    { FUNC_STATICDEF, "static"    },
    { FUNC_FRAME,     "frame"     },
    { FUNC_USERFAR,   "userfar"   },
    { FUNC_HIDDEN,    "hidden"    },
    { FUNC_THUNK,     "thunk"     },
    { FUNC_BOTTOMBP,  "bottombp"  },
    { FUNC_NORET_PENDING, "noret_pending" },
    { FUNC_SP_READY,  "sp_ready"  },
    { FUNC_PURGED_OK, "purged_ok" },
    { FUNC_TAIL,      "tail"      },
    { FUNC_OUTLINE,   "outline"   },
};

json flags_to_names(uint64 flags)
{
    json out = json::array();
    for (const func_flag_name_t &e : kFuncFlags)
        if ((flags & e.flag) != 0)
            out.push_back(e.name);
    return out;
}

uint64 flag_from_name(const std::string &s)
{
    for (const func_flag_name_t &e : kFuncFlags)
        if (s == e.name)
            return e.flag;
    throw std::runtime_error("unknown function flag '" + s + "'");
}

// The signature files IDA has loaded, with how many functions each matched.
json cmd_signatures(const json &)
{
    const int qty = get_idasgn_qty();

    json sigs = json::array();
    for (int i = 0; i < qty; i++)
    {
        qstring name;
        qstring optlibs;
        const int32 matched = get_idasgn_desc(&name, &optlibs, i);
        sigs.push_back({
            { "index",    i },
            { "name",     name.c_str() },
            { "optlibs",  optlibs.c_str() },
            // Negative means the count is unknown rather than zero.
            { "matched",  matched < 0 ? json(nullptr) : json(matched) },
            { "state",    calc_idasgn_state(i) },
        });
    }

    return {
        { "count",      qty },
        { "current",    get_current_idasgn() },
        { "signatures", sigs },
    };
}

// Applies a signature file by name. Matching is planned, so the effect appears once
// analysis next runs over the candidate addresses.
json cmd_apply_signature(const json &params)
{
    const std::string name = require_str(params, "name");

    const int rc = plan_to_apply_idasgn(name.c_str());
    if (rc == 0)
        throw std::runtime_error("signature file not found or not applicable: " + name);

    return { { "name", name }, { "planned", rc }, { "success", true } };
}

// Splits the function list by origin. Library functions are what FLIRT matched;
// everything else is the program's own code.
json cmd_function_origins(const json &params)
{
    const size_t limit = opt_limit(params, 200);
    const std::string want = opt_str(params, "kind", "user");

    const bool want_lib   = want == "library";
    const bool want_thunk = want == "thunk";
    const bool want_all   = want == "all";
    if (!want_lib && !want_thunk && !want_all && want != "user")
        throw std::runtime_error("kind must be one of: user, library, thunk, all");

    size_t lib_total = 0;
    size_t thunk_total = 0;
    const size_t total = get_func_qty();

    json items = json::array();
    for (size_t i = 0; i < total; i++)
    {
        func_t *f = getn_func(i);
        if (f == nullptr)
            continue;

        const bool is_lib   = (f->flags & FUNC_LIB) != 0;
        const bool is_thunk = (f->flags & FUNC_THUNK) != 0;
        if (is_lib)
            lib_total++;
        if (is_thunk)
            thunk_total++;

        const bool keep = want_all
                        || (want_lib && is_lib)
                        || (want_thunk && is_thunk)
                        || (want == "user" && !is_lib && !is_thunk);
        if (!keep || items.size() >= limit)
            continue;

        items.push_back({
            { "ea",    ea_hex(f->start_ea) },
            { "name",  func_name_of(f->start_ea) },
            { "size",  (uint64)(f->end_ea - f->start_ea) },
            { "flags", flags_to_names(f->flags) },
        });
    }

    return {
        { "kind",      want },
        { "total",     (uint64)total },
        { "library",   (uint64)lib_total },
        { "thunks",    (uint64)thunk_total },
        { "user",      (uint64)(total - lib_total - thunk_total) },
        { "returned",  (int)items.size() },
        { "functions", items },
    };
}

// Reads the flags of one function, named rather than as a bit mask.
json cmd_func_flags(const json &params)
{
    func_t &f = require_func(params);
    return {
        { "ea",    ea_hex(f.start_ea) },
        { "name",  func_name_of(f.start_ea) },
        { "raw",   (uint64)f.flags },
        { "flags", flags_to_names(f.flags) },
    };
}

// Sets or clears one flag. Marking a function as library excludes it from the user
// listing, which is how a reverser prunes recognised code by hand.
json cmd_set_func_flag(const json &params)
{
    func_t &f = require_func(params);
    const std::string flag_name = require_str(params, "flag");
    const bool on = params.value("on", true);

    const uint64 flag = flag_from_name(flag_name);
    if (!set_func_flag(f.start_ea, flag, on))
        throw std::runtime_error("failed to change flag '" + flag_name + "'");

    func_t *updated = get_func(f.start_ea);
    return {
        { "ea",      ea_hex(f.start_ea) },
        { "flag",    flag_name },
        { "on",      on },
        { "flags",   flags_to_names(updated != nullptr ? updated->flags : 0) },
        { "success", true },
    };
}

const command_entry_t kCommands[] = {
    { "signatures",       cmd_signatures       },
    { "apply_signature",  cmd_apply_signature  },
    { "function_origins", cmd_function_origins },
    { "func_flags",       cmd_func_flags       },
    { "set_func_flag",    cmd_set_func_flag    },
};

}  // namespace

void register_signature_commands(CommandDispatcher &dispatcher)
{
    dispatcher.register_table(kCommands);
}

}  // namespace ida_hive
