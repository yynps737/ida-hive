#include "ida_hive/pch.hpp"

#include <ida.hpp>
#include <idp.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <ua.hpp>
#include <xref.hpp>
#include <gdl.hpp>
#include <lines.hpp>

#include "ida_hive/commands.hpp"
#include "ida_hive/util.hpp"
#include "ida_hive/params.hpp"
#include "ida_hive/xrefs.hpp"

#include <queue>
#include <set>

namespace ida_hive {
namespace {

json cmd_basic_blocks(const json &params)
{
    func_t &f = require_func(params);

    qflow_chart_t fc;
    fc.create("", &f, BADADDR, BADADDR, FC_NOEXT);

    json blocks = json::array();
    for (int i = 0; i < fc.size(); i++)
    {
        const qbasic_block_t& bb = fc.blocks[i];
        json succs = json::array();
        for (int j = 0; j < fc.nsucc(i); j++)
            succs.push_back(fc.succ(i, j));

        json preds = json::array();
        for (int j = 0; j < fc.npred(i); j++)
            preds.push_back(fc.pred(i, j));

        blocks.push_back({
            {"id",     i},
            {"start",  ea_hex(bb.start_ea)},
            {"end",    ea_hex(bb.end_ea)},
            {"size",   (size_t)(bb.end_ea - bb.start_ea)},
            {"succs",  succs},
            {"preds",  preds},
        });
    }

    qstring func_name;
    get_func_name(&func_name, f.start_ea);

    return {
        {"ea",     ea_hex(f.start_ea)},
        {"name",   func_name.c_str()},
        {"blocks", blocks},
        {"count",  fc.size()},
    };
}

json cmd_callgraph(const json &params)
{
    auto roots = params.at("roots");
    int max_depth = params.value("depth", 3);

    json nodes = json::array();
    json edges = json::array();
    std::set<ea_t> visited;

    // Breadth-first so the depth cap trims whole levels, not arbitrary paths.
    struct QueueItem { ea_t ea; int depth; };
    std::queue<QueueItem> q;

    for (auto& r : roots)
    {
        ea_t ea = parse_ea(r);
        func_t* f = get_func(ea);
        if (f) q.push({f->start_ea, 0});
    }

    while (!q.empty() && nodes.size() < 200)
    {
        auto [ea, depth] = q.front();
        q.pop();

        if (visited.count(ea)) continue;
        visited.insert(ea);

        func_t* f = get_func(ea);
        if (!f) continue;

        qstring name;
        get_func_name(&name, f->start_ea);

        nodes.push_back({
            {"ea",    ea_hex(f->start_ea)},
            {"name",  name.c_str()},
            {"depth", depth},
        });

        if (depth >= max_depth) continue;

        std::set<ea_t> seen;
        for (const call_edge_t &e : collect_callees(f->start_ea, f->end_ea))
        {
            if (!seen.insert(e.callee_ea).second)
                continue;
            edges.push_back({
                {"from", ea_hex(f->start_ea)},
                {"to",   ea_hex(e.callee_ea)},
            });
            if (!visited.count(e.callee_ea))
                q.push({e.callee_ea, depth + 1});
        }
    }

    return {{"nodes", nodes}, {"edges", edges}};
}

json cmd_insn_query(const json &params)
{
    std::string mnemonic = params.value("mnemonic", std::string{});
    size_t limit = opt_limit(params, 50);

    ea_t start, end;
    if (params.contains("ea"))
    {
        ea_t ea = parse_ea(params["ea"]);
        func_t* f = get_func(ea);
        if (!f) throw std::runtime_error("No function at address");
        start = f->start_ea;
        end = f->end_ea;
    }
    else
    {
        start = inf_get_min_ea();
        end = inf_get_max_ea();
    }

    json results = json::array();
    ea_t curr = start;
    insn_t insn;

    while (curr < end && curr != BADADDR && results.size() < limit)
    {
        int len = decode_insn(&insn, curr);
        if (len <= 0) { curr = next_head(curr, end); continue; }

        qstring mnem;
        print_insn_mnem(&mnem, curr);

        bool match = mnemonic.empty() ||
                     std::string(mnem.c_str()).find(mnemonic) != std::string::npos;

        if (match)
        {
            qstring disasm_line;
            generate_disasm_line(&disasm_line, curr, GENDSM_REMOVE_TAGS);

            results.push_back({
                {"ea",       ea_hex(curr)},
                {"mnemonic", mnem.c_str()},
                {"text",     disasm_line.c_str()},
                {"size",     len},
            });
        }

        curr += len;
    }

    return {{"instructions", results}, {"count", results.size()}};
}

json cmd_func_profile(const json &params)
{
    func_t &f = require_func(params);

    qstring name;
    get_func_name(&name, f.start_ea);
    size_t fsize = (size_t)(f.end_ea - f.start_ea);

    int caller_count = 0;
    xrefblk_t xb;
    for (bool ok = xb.first_to(f.start_ea, XREF_ALL); ok; ok = xb.next_to())
        if (xb.iscode) caller_count++;

    json callees = json::array();
    json strings = json::array();
    std::set<ea_t> seen_callees;

    for (const call_edge_t &e : collect_callees(f.start_ea, f.end_ea))
        callees.push_back({{"ea", ea_hex(e.callee_ea)}, {"name", func_name_of(e.callee_ea)}});

    for (const string_ref_t &s : collect_string_refs(f.start_ea, f.end_ea, 20))
        strings.push_back({{"ea", ea_hex(s.ea)}, {"string", s.text}});

    return {
        {"ea",       ea_hex(f.start_ea)},
        {"name",     name.c_str()},
        {"size",     fsize},
        {"callers",  caller_count},
        {"callees",  callees},
        {"strings",  strings},
    };
}

const command_entry_t kCommands[] = {
    { "basic_blocks", cmd_basic_blocks },
    { "callgraph",    cmd_callgraph },
    { "insn_query",   cmd_insn_query },
    { "func_profile", cmd_func_profile },
};

}  // namespace

void register_graph_commands(CommandDispatcher &dispatcher)
{
    dispatcher.register_table(kCommands);
}

}  // namespace ida_hive
