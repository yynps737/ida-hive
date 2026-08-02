#include "ida_hive/pch.hpp"

#include <ida.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <hexrays.hpp>

#include "ida_hive/commands.hpp"
#include "ida_hive/util.hpp"
#include "ida_hive/params.hpp"

namespace ida_hive {
namespace {

// Microcode is the decompiler's intermediate representation. Reading it exposes the
// analysis the pseudocode is derived from — call arguments, value ranges, register
// liveness — none of which survive into the printed C.

struct maturity_name_t
{
    mba_maturity_t level;
    const char    *name;
};

// Ordered as the decompiler runs them, weakest first.
const maturity_name_t kMaturities[] = {
    { MMAT_GENERATED,    "generated"    },
    { MMAT_PREOPTIMIZED, "preoptimized" },
    { MMAT_LOCOPT,       "locopt"       },
    { MMAT_CALLS,        "calls"        },
    { MMAT_GLBOPT1,      "glbopt1"      },
    { MMAT_GLBOPT2,      "glbopt2"      },
    { MMAT_GLBOPT3,      "glbopt3"      },
    { MMAT_LVARS,        "lvars"        },
};

const char *maturity_to_name(mba_maturity_t m)
{
    for (const maturity_name_t &e : kMaturities)
        if (e.level == m)
            return e.name;
    return "unknown";
}

// Callers name a maturity rather than an enum value; the default matches what the
// pseudocode is built from.
mba_maturity_t maturity_from_name(const std::string &s)
{
    if (s.empty())
        return MMAT_GLBOPT3;
    for (const maturity_name_t &e : kMaturities)
        if (s == e.name)
            return e.level;
    throw std::runtime_error("unknown maturity '" + s + "'");
}

// Owns the mba_t returned by gen_microcode, which the caller must delete.
class mba_holder_t
{
public:
    explicit mba_holder_t(mba_t *p) : ptr_(p) {}
    ~mba_holder_t() { delete ptr_; }
    mba_holder_t(const mba_holder_t &) = delete;
    mba_holder_t &operator=(const mba_holder_t &) = delete;
    mba_t *get() const { return ptr_; }

private:
    mba_t *ptr_;
};

mba_t *generate(func_t &f, mba_maturity_t level)
{
    if (!init_hexrays_plugin())
        throw std::runtime_error("Hex-Rays decompiler is not available");

    hexrays_failure_t hf;
    mba_ranges_t mbr(&f);
    mba_t *mba = gen_microcode(mbr, &hf, nullptr, DECOMP_NO_CACHE, level);
    if (mba == nullptr)
        throw std::runtime_error(hf.desc().empty()
                                 ? std::string("microcode generation failed")
                                 : std::string(hf.desc().c_str()));
    return mba;
}

// Full microcode listing for a function, one entry per basic block.
json cmd_microcode(const json &params)
{
    func_t &f = require_func(params);
    const mba_maturity_t level = maturity_from_name(opt_str(params, "maturity"));
    const size_t max_insns = opt_limit(params, 2000);

    mba_holder_t mba(generate(f, level));

    size_t emitted = 0;
    json blocks = json::array();
    for (int i = 0; i < mba.get()->qty; i++)
    {
        const mblock_t *blk = mba.get()->natural[i];
        if (blk == nullptr)
            continue;

        json insns = json::array();
        for (const minsn_t *ins = blk->head; ins != nullptr && emitted < max_insns;
             ins = ins->next, emitted++)
        {
            qstring text;
            ins->print(&text);
            tag_remove(&text, text);
            insns.push_back({
                { "ea",   ea_hex(ins->ea) },
                { "text", text.c_str() },
            });
        }

        blocks.push_back({
            { "index",        i },
            { "start",        ea_hex(blk->start) },
            { "end",          ea_hex(blk->end) },
            { "instructions", insns },
        });
    }

    return {
        { "ea",        ea_hex(f.start_ea) },
        { "name",      func_name_of(f.start_ea) },
        { "maturity",  maturity_to_name(mba.get()->maturity) },
        { "blocks",    (int)mba.get()->qty },
        { "truncated", emitted >= max_insns },
        { "microcode", blocks },
    };
}

// Shape only. Cheap enough to run over many functions when the listing is not needed.
json cmd_microcode_stats(const json &params)
{
    func_t &f = require_func(params);
    const mba_maturity_t level = maturity_from_name(opt_str(params, "maturity"));

    mba_holder_t mba(generate(f, level));

    int total = 0;
    int max_block = 0;
    for (int i = 0; i < mba.get()->qty; i++)
    {
        const mblock_t *blk = mba.get()->natural[i];
        if (blk == nullptr)
            continue;
        int n = 0;
        for (const minsn_t *ins = blk->head; ins != nullptr; ins = ins->next)
            n++;
        total += n;
        if (n > max_block)
            max_block = n;
    }

    return {
        { "ea",                 ea_hex(f.start_ea) },
        { "name",               func_name_of(f.start_ea) },
        { "maturity",           maturity_to_name(mba.get()->maturity) },
        { "blocks",             (int)mba.get()->qty },
        { "instructions",       total },
        { "largest_block",      max_block },
    };
}

// The maturity ladder, so a caller can pick a level without guessing at names.
json cmd_microcode_maturities(const json &)
{
    json levels = json::array();
    for (const maturity_name_t &e : kMaturities)
        levels.push_back(e.name);
    return { { "maturities", levels }, { "default", "glbopt3" } };
}

const command_entry_t kCommands[] = {
    { "microcode",            cmd_microcode            },
    { "microcode_stats",      cmd_microcode_stats      },
    { "microcode_maturities", cmd_microcode_maturities },
};

}  // namespace

void register_microcode_commands(CommandDispatcher &dispatcher)
{
    dispatcher.register_table(kCommands);
}

}  // namespace ida_hive
