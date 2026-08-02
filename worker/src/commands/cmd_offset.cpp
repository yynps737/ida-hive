#include "ida_hive/pch.hpp"

#include <ida.hpp>
#include <bytes.hpp>
#include <xref.hpp>
#include <offset.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <segment.hpp>

#include "ida_hive/commands.hpp"
#include "ida_hive/util.hpp"
#include "ida_hive/params.hpp"

namespace ida_hive {
namespace {

// An immediate that happens to equal an address stays a bare number until it is
// marked as a reference. Marking it makes IDA resolve it to a name, create the xref,
// and carry it into the pseudocode — which is why a pointer table left unmarked
// reads as a list of magic constants.

struct reftype_name_t
{
    uint32      type;
    const char *name;
};

const reftype_name_t kRefTypes[] = {
    { REF_OFF8,   "off8"   },
    { REF_OFF16,  "off16"  },
    { REF_OFF32,  "off32"  },
    { REF_OFF64,  "off64"  },
    { REF_LOW8,   "low8"   },
    { REF_LOW16,  "low16"  },
    { REF_HIGH8,  "high8"  },
    { REF_HIGH16, "high16" },
};

const char *reftype_to_name(uint32 t)
{
    for (const reftype_name_t &e : kRefTypes)
        if (e.type == (t & REFINFO_TYPE))
            return e.name;
    return "unknown";
}

uint32 reftype_from_name(const std::string &s)
{
    if (s.empty())
        return get_default_reftype(BADADDR);
    for (const reftype_name_t &e : kRefTypes)
        if (s == e.name)
            return e.type;
    throw std::runtime_error("unknown reference type '" + s + "'");
}

// Operand index; -1 addresses all operands, which is what a data item wants.
int operand_index(const json &params)
{
    return (int)params.value("operand", 0);
}

// Marks an operand as an address reference.
json cmd_set_offset(const json &params)
{
    const ea_t ea = require_ea(params);
    const int n = operand_index(params);
    const uint32 type = reftype_from_name(opt_str(params, "type"));
    const ea_t base = params.contains("base") ? require_ea(params, "base") : 0;
    const ea_t target = params.contains("target") ? require_ea(params, "target") : BADADDR;

    if (!op_offset(ea, n, type, target, base))
        throw std::runtime_error("failed to mark operand " + std::to_string(n)
                                 + " at " + ea_hex(ea) + " as an offset");

    refinfo_t ri;
    const bool has = get_refinfo(&ri, ea, n);
    return {
        { "ea",      ea_hex(ea) },
        { "operand", n },
        { "type",    has ? reftype_to_name(ri.flags) : "unknown" },
        { "base",    has ? ea_hex(ri.base) : ea_hex(base) },
        { "success", true },
    };
}

// Removes the reference marking, returning the operand to a plain number.
json cmd_clear_offset(const json &params)
{
    const ea_t ea = require_ea(params);
    const int n = operand_index(params);

    clr_op_type(ea, n);
    return { { "ea", ea_hex(ea) }, { "operand", n }, { "success", true } };
}

// Reports whether an operand carries reference info, and what it resolves to.
json cmd_get_offset(const json &params)
{
    const ea_t ea = require_ea(params);
    const int n = operand_index(params);

    refinfo_t ri;
    if (!get_refinfo(&ri, ea, n))
        return { { "ea", ea_hex(ea) }, { "operand", n }, { "is_offset", false } };

    const ea_t target = ri.target != BADADDR ? ri.target : ri.base;
    qstring nm;
    get_name(&nm, target);

    return {
        { "ea",        ea_hex(ea) },
        { "operand",   n },
        { "is_offset", true },
        { "type",      reftype_to_name(ri.flags) },
        { "base",      ea_hex(ri.base) },
        { "target",    ri.target == BADADDR ? json(nullptr) : json(ea_hex(ri.target)) },
        { "name",      nm.empty() ? json(nullptr) : json(nm.c_str()) },
    };
}

// Finds immediates that look like addresses but are not yet marked. This is the scan
// that turns an unmarked pointer table into navigable references.
json cmd_offset_candidates(const json &params)
{
    const ea_t start = require_ea(params, "start");
    const ea_t end   = params.contains("end") ? require_ea(params, "end")
                                              : inf_get_max_ea();
    const size_t limit = opt_limit(params, 200);

    json items = json::array();
    for (ea_t ea = start; ea < end && ea != BADADDR && items.size() < limit;
         ea = next_head(ea, end))
    {
        // Already marked operands are not candidates.
        refinfo_t ri;
        if (get_refinfo(&ri, ea, 0))
            continue;

        const ea_t base = can_be_off32(ea);
        if (base == BADADDR)
            continue;

        qstring nm;
        get_name(&nm, base);
        items.push_back({
            { "ea",     ea_hex(ea) },
            { "target", ea_hex(base) },
            { "name",   nm.empty() ? json(nullptr) : json(nm.c_str()) },
        });
    }

    return {
        { "start",      ea_hex(start) },
        { "end",        ea_hex(end) },
        { "count",      (int)items.size() },
        { "candidates", items },
    };
}

const command_entry_t kCommands[] = {
    { "set_offset",        cmd_set_offset        },
    { "clear_offset",      cmd_clear_offset      },
    { "get_offset",        cmd_get_offset        },
    { "offset_candidates", cmd_offset_candidates },
};

}  // namespace

void register_offset_commands(CommandDispatcher &dispatcher)
{
    dispatcher.register_table(kCommands);
}

}  // namespace ida_hive
