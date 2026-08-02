#include "ida_hive/pch.hpp"

#include <ida.hpp>
#include <idp.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <nalt.hpp>
#include <range.hpp>
#include <tryblks.hpp>
#include <regfinder.hpp>
#include <problems.hpp>
#include <fixup.hpp>
#include <segregs.hpp>

#include "ida_hive/commands.hpp"
#include "ida_hive/util.hpp"
#include "ida_hive/params.hpp"

namespace ida_hive {
namespace {

// Reads one jump-table slot. Entries are stored at the table's element width, not
// always pointer width.
uint64 read_table_slot(ea_t slot, int element_size)
{
    switch (element_size)
    {
        case 1:  return get_byte(slot);
        case 2:  return get_word(slot);
        case 4:  return get_dword(slot);
        default: return get_qword(slot);
    }
}

// Table entries are offsets under the shift encoded in flags, relative to elbase;
// the switch segment's base stands in when SWI_ELBASE is unset.
ea_t decode_target(const switch_info_t &si, uint64 raw)
{
    ea_t base = (si.flags & SWI_ELBASE) != 0 ? si.elbase : 0;
    ea_t off  = (ea_t)(raw << si.get_shift());
    return si.is_subtract() ? base - off : base + off;
}

json switch_targets(const switch_info_t &si)
{
    json targets = json::array();
    const int count = si.get_jtable_size();
    if (si.jumps == BADADDR || count <= 0)
        return targets;

    const int esize = si.get_jtable_element_size();
    for (int i = 0; i < count && targets.size() < 4096; i++)
    {
        ea_t tgt = decode_target(si, read_table_slot(si.jumps + (ea_t)i * esize, esize));
        qstring nm;
        get_func_name(&nm, tgt);
        targets.push_back({
            { "index",  i },
            { "target", ea_hex(tgt) },
            { "func",   nm.empty() ? json(nullptr) : json(nm.c_str()) },
        });
    }
    return targets;
}

// Resolves the indirect branch IDA's analysis already recovered, so a switch reads
// as its case targets instead of an unresolved jump.
json cmd_switch_info(const json &params)
{
    ea_t ea = require_ea(params);

    switch_info_t si;
    if (get_switch_info(&si, ea) <= 0)
    {
        // An address inside the idiom still resolves through its parent.
        ea_t parent = get_switch_parent(ea);
        if (parent == BADADDR || get_switch_info(&si, parent) <= 0)
            return { { "ea", ea_hex(ea) }, { "is_switch", false } };
        ea = parent;
    }

    return {
        { "ea",            ea_hex(ea) },
        { "is_switch",     true },
        { "start_ea",      ea_hex(si.startea) },
        { "jump_table",    ea_hex(si.jumps) },
        { "element_size",  si.get_jtable_element_size() },
        { "cases",         (int)si.ncases },
        { "table_entries", si.get_jtable_size() },
        { "lowest_case",   (int64_t)si.get_lowcase() },
        { "default_jump",  si.defjump == BADADDR ? json(nullptr) : json(ea_hex(si.defjump)) },
        { "reg",           si.regnum },
        { "sparse",        si.is_sparse() },
        { "indirect",      si.is_indirect() },
        { "targets",       switch_targets(si) },
    };
}

// A handler body is itself a set of ranges; the first one is its entry.
json handler_ranges(const rangevec_t &rv, const char *kind)
{
    json out = json::array();
    for (size_t i = 0; i < rv.size(); i++)
        out.push_back({
            { "start", ea_hex(rv[i].start_ea) },
            { "end",   ea_hex(rv[i].end_ea) },
            { "kind",  kind },
        });
    return out;
}

// C++ and SEH exception structure, which is invisible in both the disassembly and
// the pseudocode.
json cmd_try_blocks(const json &params)
{
    func_t &f = require_func(params);

    tryblks_t tbv;
    get_tryblks(&tbv, range_t(f.start_ea, f.end_ea));

    json blocks = json::array();
    for (size_t i = 0; i < tbv.size(); i++)
    {
        const tryblk_t &tb = tbv[i];

        json handlers = json::array();
        if (tb.is_cpp())
        {
            const catchvec_t &cv = tb.cpp();
            for (size_t j = 0; j < cv.size(); j++)
            {
                json h = handler_ranges(cv[j], "catch");
                for (auto &e : h)
                {
                    e["type_id"] = (int64_t)cv[j].type_id;   // -1 means catch(...)
                    handlers.push_back(e);
                }
            }
        }
        else if (tb.is_seh())
        {
            for (auto &e : handler_ranges(tb.seh(), "seh_handler"))
                handlers.push_back(e);
            for (auto &e : handler_ranges(tb.seh().filter, "seh_filter"))
                handlers.push_back(e);
        }

        json guarded = json::array();
        for (size_t j = 0; j < tb.size(); j++)
            guarded.push_back({
                { "start", ea_hex(tb[j].start_ea) },
                { "end",   ea_hex(tb[j].end_ea) },
            });

        blocks.push_back({
            { "kind",     tb.is_cpp() ? "cpp" : "seh" },
            { "level",    (int)tb.level },
            { "guarded",  guarded },
            { "handlers", handlers },
        });
    }

    return { { "ea", ea_hex(f.start_ea) }, { "count", (int)tbv.size() }, { "blocks", blocks } };
}

// IDA's own value propagation: what a register holds at an address, without reading
// the pseudocode back.
json cmd_reg_value(const json &params)
{
    ea_t ea = require_ea(params);
    std::string regname = require_str(params, "reg");

    int regnum = str2reg(regname.c_str());
    if (regnum < 0)
        throw std::runtime_error("unknown register: " + regname);

    uint64 val = 0;
    int rc = find_reg_value(&val, ea, regnum);

    // 1 resolved to a constant, 0 not constant here, negative means analysis failed.
    const char *status = rc == 1 ? "constant" : (rc == 0 ? "not_constant" : "failed");
    return {
        { "ea",       ea_hex(ea) },
        { "reg",      regname },
        { "resolved", rc == 1 },
        { "value",    rc == 1 ? json(val) : json(nullptr) },
        { "status",   status },
    };
}

// Everything IDA flagged as questionable during analysis.
json cmd_problems(const json &params)
{
    const size_t limit = opt_limit(params, 100);

    static const struct { problist_id_t id; const char *name; } kinds[] = {
        { PR_NOBASE,    "no_base"    }, { PR_NONAME,     "no_name"    },
        { PR_NOFOP,     "no_fop"     }, { PR_NOCMT,      "no_comment" },
        { PR_NOXREFS,   "no_xrefs"   }, { PR_JUMP,       "jump"       },
        { PR_DISASM,    "disasm"     }, { PR_HEAD,       "head"       },
        { PR_ILLADDR,   "bad_addr"   }, { PR_MANYLINES,  "many_lines" },
        { PR_BADSTACK,  "bad_stack"  }, { PR_ATTN,       "attention"  },
        { PR_FINAL,     "final"      }, { PR_ROLLED,     "rolled"     },
        { PR_COLLISION, "collision"  }, { PR_DECIMP,     "decimp"     },
    };

    json items = json::array();
    for (const auto &k : kinds)
    {
        for (ea_t p = get_problem(k.id, 0);
             p != BADADDR && items.size() < limit;
             p = get_problem(k.id, p + 1))
        {
            qstring desc;
            get_problem_desc(&desc, k.id, p);
            items.push_back({
                { "ea",          ea_hex(p) },
                { "kind",        k.name },
                { "description", desc.c_str() },
            });
        }
    }
    return { { "count", (int)items.size() }, { "problems", items } };
}

// Relocations, which reveal the operands the loader rewrote.
json cmd_fixups(const json &params)
{
    const size_t limit = opt_limit(params, 200);
    const ea_t start = params.contains("start") ? require_ea(params, "start") : 0;

    json items = json::array();
    for (ea_t p = get_first_fixup_ea(); p != BADADDR && items.size() < limit;
         p = get_next_fixup_ea(p))
    {
        if (p < start)
            continue;

        fixup_data_t fd;
        if (!fd.get(p))
            continue;

        items.push_back({
            { "ea",     ea_hex(p) },
            { "type",   (int)fd.get_type() },
            { "base",   ea_hex(fd.get_base()) },
            { "target", ea_hex(fd.get_base() + fd.off) },
        });
    }
    return { { "count", (int)items.size() }, { "fixups", items } };
}

// Segment register values, which decide addressing on segmented targets.
json cmd_seg_regs(const json &params)
{
    ea_t ea = require_ea(params);

    json regs = json::array();
    for (int r = PH.reg_first_sreg; r <= PH.reg_last_sreg; r++)
    {
        sel_t v = get_sreg(ea, r);
        if (v == BADSEL)
            continue;
        regs.push_back({
            { "reg",   PH.reg_names[r] },
            { "value", ea_hex((ea_t)v) },
        });
    }
    return { { "ea", ea_hex(ea) }, { "registers", regs } };
}

const command_entry_t kCommands[] = {
    { "switch_info", cmd_switch_info },
    { "try_blocks",  cmd_try_blocks  },
    { "reg_value",   cmd_reg_value   },
    { "problems",    cmd_problems    },
    { "fixups",      cmd_fixups      },
    { "seg_regs",    cmd_seg_regs    },
};

}  // namespace

void register_flow_commands(CommandDispatcher &dispatcher)
{
    dispatcher.register_table(kCommands);
}

}  // namespace ida_hive
