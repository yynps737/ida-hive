// cmd_graph.cpp - Graph/CFG commands: basic_blocks, callgraph, insn_query
#include "../pch.h"

#include <ida.hpp>
#include <idp.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <ua.hpp>
#include <xref.hpp>
#include <gdl.hpp>
#include <lines.hpp>

#include "cmd_graph.h"
#include "../util.h"

#include <queue>
#include <set>

void register_graph_commands(CommandDispatcher& dispatcher)
{
    // ---- basic_blocks ----
    // Get control flow graph basic blocks for a function
    // params: {ea: string}
    dispatcher.register_command("basic_blocks", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
        func_t* f = get_func(ea);
        if (!f)
            throw std::runtime_error("No function at given address");

        qflow_chart_t fc;
        fc.create("", f, BADADDR, BADADDR, FC_NOEXT);

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
        get_func_name(&func_name, f->start_ea);

        return {
            {"ea",     ea_hex(f->start_ea)},
            {"name",   func_name.c_str()},
            {"blocks", blocks},
            {"count",  fc.size()},
        };
    });

    // ---- callgraph ----
    // Build bounded call graph from root functions
    // params: {roots: [string], depth?: int}
    dispatcher.register_command("callgraph", [](const json& params) -> json {
        auto roots = params.at("roots");
        int max_depth = params.value("depth", 3);

        json nodes = json::array();
        json edges = json::array();
        std::set<ea_t> visited;

        // BFS
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

            // Find callees
            ea_t curr = f->start_ea;
            while (curr < f->end_ea && curr != BADADDR)
            {
                xrefblk_t xb;
                for (bool ok = xb.first_from(curr, XREF_FAR); ok; ok = xb.next_from())
                {
                    if (!xb.iscode) continue;
                    func_t* callee = get_func(xb.to);
                    if (!callee) continue;

                    edges.push_back({
                        {"from", ea_hex(f->start_ea)},
                        {"to",   ea_hex(callee->start_ea)},
                    });

                    if (!visited.count(callee->start_ea))
                        q.push({callee->start_ea, depth + 1});
                }
                curr = next_head(curr, f->end_ea);
            }
        }

        return {{"nodes", nodes}, {"edges", edges}};
    });

    // ---- insn_query ----
    // Search instructions by mnemonic/operand within a function or range
    // params: {mnemonic?: string, ea?: string, limit?: int}
    dispatcher.register_command("insn_query", [](const json& params) -> json {
        std::string mnemonic = params.value("mnemonic", std::string{});
        size_t limit = params.value("limit", 50);

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
    });

    // ---- func_profile ----
    // Quick function summary: size, callees, callers, strings
    // params: {ea: string}
    dispatcher.register_command("func_profile", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
        func_t* f = get_func(ea);
        if (!f)
            throw std::runtime_error("No function at given address");

        qstring name;
        get_func_name(&name, f->start_ea);
        size_t fsize = (size_t)(f->end_ea - f->start_ea);

        // Count callers
        int caller_count = 0;
        xrefblk_t xb;
        for (bool ok = xb.first_to(f->start_ea, XREF_ALL); ok; ok = xb.next_to())
            if (xb.iscode) caller_count++;

        // Collect callees + strings
        json callees = json::array();
        json strings = json::array();
        std::set<ea_t> seen_callees;

        ea_t curr = f->start_ea;
        while (curr < f->end_ea && curr != BADADDR)
        {
            xrefblk_t xb2;
            for (bool ok = xb2.first_from(curr, XREF_ALL); ok; ok = xb2.next_from())
            {
                if (xb2.iscode)
                {
                    func_t* callee = get_func(xb2.to);
                    if (callee && !seen_callees.count(callee->start_ea))
                    {
                        seen_callees.insert(callee->start_ea);
                        qstring cname;
                        get_func_name(&cname, callee->start_ea);
                        callees.push_back({{"ea", ea_hex(callee->start_ea)}, {"name", cname.c_str()}});
                    }
                }
                else
                {
                    // Check if data ref points to a string
                    size_t slen = get_max_strlit_length(xb2.to, STRTYPE_C);
                    if (slen > 2 && strings.size() < 20)
                    {
                        std::vector<uint8_t> buf(slen + 1, 0);
                        get_bytes(buf.data(), slen, xb2.to);
                        strings.push_back({
                            {"ea", ea_hex(xb2.to)},
                            {"string", std::string(reinterpret_cast<char*>(buf.data()))},
                        });
                    }
                }
            }
            curr = next_head(curr, f->end_ea);
        }

        return {
            {"ea",       ea_hex(f->start_ea)},
            {"name",     name.c_str()},
            {"size",     fsize},
            {"callers",  caller_count},
            {"callees",  callees},
            {"strings",  strings},
        };
    });
}
