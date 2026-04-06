// cmd_composite.cpp - Composite analysis commands that aggregate multiple queries
#include "../pch.h"

#include <ida.hpp>
#include <idp.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <lines.hpp>
#include <ua.hpp>
#include <xref.hpp>
#include <segment.hpp>
#include <hexrays.hpp>
#include <nalt.hpp>
#include <gdl.hpp>
#include <entry.hpp>
#include <strlist.hpp>

#include "cmd_composite.h"
#include "../util.h"

#include <set>
#include <queue>

void register_composite_commands(CommandDispatcher& dispatcher)
{
    // ---- analyze_function ----
    // Deep single-function analysis: decompile + disasm + xrefs + strings + callees + basic blocks
    // params: {ea: string}
    dispatcher.register_command("analyze_function", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
        func_t* f = get_func(ea);
        if (!f)
            throw std::runtime_error("No function at address");

        qstring func_name;
        get_func_name(&func_name, f->start_ea);
        size_t fsize = (size_t)(f->end_ea - f->start_ea);

        // Pseudocode
        std::string pseudocode;
        if (init_hexrays_plugin())
        {
            hexrays_failure_t hf;
            cfuncptr_t cfunc = decompile(f, &hf);
            if (cfunc)
            {
                const strvec_t& sv = cfunc->get_pseudocode();
                for (size_t i = 0; i < sv.size(); i++)
                {
                    qstring clean;
                    tag_remove(&clean, sv[i].line);
                    pseudocode += clean.c_str();
                    pseudocode += "\n";
                }
            }
        }

        // Callers
        json callers = json::array();
        xrefblk_t xb;
        for (bool ok = xb.first_to(f->start_ea, XREF_ALL); ok && callers.size() < 20; ok = xb.next_to())
        {
            if (!xb.iscode) continue;
            func_t* caller = get_func(xb.from);
            if (!caller) continue;
            qstring cname;
            get_func_name(&cname, caller->start_ea);
            callers.push_back({{"ea", ea_hex(caller->start_ea)}, {"name", cname.c_str()}});
        }

        // Callees + strings
        json callees = json::array();
        json strings = json::array();
        std::set<ea_t> seen;

        ea_t curr = f->start_ea;
        while (curr < f->end_ea && curr != BADADDR)
        {
            xrefblk_t xb2;
            for (bool ok = xb2.first_from(curr, XREF_ALL); ok; ok = xb2.next_from())
            {
                if (xb2.iscode)
                {
                    func_t* callee = get_func(xb2.to);
                    if (callee && !seen.count(callee->start_ea))
                    {
                        seen.insert(callee->start_ea);
                        qstring n;
                        get_func_name(&n, callee->start_ea);
                        callees.push_back({{"ea", ea_hex(callee->start_ea)}, {"name", n.c_str()}});
                    }
                }
                else
                {
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

        // Basic block count
        qflow_chart_t fc;
        fc.create("", f, BADADDR, BADADDR, FC_NOEXT);

        return {
            {"ea",          ea_hex(f->start_ea)},
            {"name",        func_name.c_str()},
            {"size",        fsize},
            {"pseudocode",  pseudocode},
            {"callers",     callers},
            {"callees",     callees},
            {"strings",     strings},
            {"block_count", fc.size()},
        };
    });

    // ---- survey_binary ----
    // One-call binary triage overview
    // params: {}
    dispatcher.register_command("survey_binary", [](const json& params) -> json {
        qstring procname = inf_get_procname();
        size_t func_count = get_func_qty();
        int seg_count = get_segm_qty();

        // Segments
        json segments = json::array();
        for (int i = 0; i < seg_count; i++)
        {
            segment_t* seg = getnseg(i);
            if (!seg) continue;
            qstring sname, sclass;
            get_segm_name(&sname, seg);
            get_segm_class(&sclass, seg);
            segments.push_back({
                {"name", sname.c_str()}, {"class", sclass.c_str()},
                {"start", ea_hex(seg->start_ea)}, {"end", ea_hex(seg->end_ea)},
                {"size", (size_t)(seg->end_ea - seg->start_ea)},
            });
        }

        // Top functions by size
        json top_funcs = json::array();
        std::vector<std::pair<size_t, ea_t>> func_sizes;
        for (size_t i = 0; i < func_count; i++)
        {
            func_t* f = getn_func(i);
            if (f) func_sizes.push_back({f->end_ea - f->start_ea, f->start_ea});
        }
        std::sort(func_sizes.rbegin(), func_sizes.rend());
        for (size_t i = 0; i < 15 && i < func_sizes.size(); i++)
        {
            qstring n;
            get_func_name(&n, func_sizes[i].second);
            top_funcs.push_back({
                {"ea", ea_hex(func_sizes[i].second)},
                {"name", n.c_str()},
                {"size", func_sizes[i].first},
            });
        }

        // Import count
        int import_modules = get_import_module_qty();

        // Top strings
        json top_strings = json::array();
        string_info_t si;
        for (size_t i = 0; get_strlist_item(&si, i) && top_strings.size() < 15; i++)
        {
            if (si.length < 5) continue;
            qstring str;
            get_strlit_contents(&str, si.ea, si.length, si.type);
            top_strings.push_back({
                {"ea", ea_hex(si.ea)}, {"string", str.c_str()}, {"length", si.length},
            });
        }

        // Entry points
        json entries = json::array();
        size_t entry_count = get_entry_qty();
        for (size_t i = 0; i < entry_count && entries.size() < 10; i++)
        {
            uval_t ord = get_entry_ordinal(i);
            ea_t entry_ea = get_entry(ord);
            qstring ename;
            get_entry_name(&ename, ord);
            entries.push_back({{"ea", ea_hex(entry_ea)}, {"name", ename.c_str()}, {"ordinal", ord}});
        }

        return {
            {"processor",       procname.c_str()},
            {"bits",            inf_is_64bit() ? 64 : 32},
            {"entry",           ea_hex(inf_get_start_ip())},
            {"min_ea",          ea_hex(inf_get_min_ea())},
            {"max_ea",          ea_hex(inf_get_max_ea())},
            {"function_count",  func_count},
            {"import_modules",  import_modules},
            {"segments",        segments},
            {"top_functions",   top_funcs},
            {"top_strings",     top_strings},
            {"entries",         entries},
        };
    });

    // ---- trace_data_flow ----
    // Follow xrefs forward or backward from an address
    // params: {ea: string, direction?: "forward"|"backward", depth?: int}
    dispatcher.register_command("trace_data_flow", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
        std::string direction = params.value("direction", std::string("forward"));
        int max_depth = params.value("depth", 5);
        bool forward = (direction != "backward");

        json nodes = json::array();
        json edges = json::array();
        std::set<ea_t> visited;

        struct Item { ea_t ea; int depth; };
        std::queue<Item> q;
        q.push({ea, 0});

        while (!q.empty() && nodes.size() < 200)
        {
            auto [cur, depth] = q.front();
            q.pop();

            if (visited.count(cur)) continue;
            visited.insert(cur);

            qstring name;
            get_ea_name(&name, cur);

            qstring disasm_line;
            generate_disasm_line(&disasm_line, cur, GENDSM_REMOVE_TAGS);

            nodes.push_back({
                {"ea", ea_hex(cur)}, {"name", name.c_str()},
                {"disasm", disasm_line.c_str()}, {"depth", depth},
            });

            if (depth >= max_depth) continue;

            xrefblk_t xb;
            if (forward)
            {
                for (bool ok = xb.first_from(cur, XREF_ALL); ok; ok = xb.next_from())
                {
                    edges.push_back({{"from", ea_hex(cur)}, {"to", ea_hex(xb.to)}, {"type", xb.iscode ? "code" : "data"}});
                    if (!visited.count(xb.to)) q.push({xb.to, depth + 1});
                }
            }
            else
            {
                for (bool ok = xb.first_to(cur, XREF_ALL); ok; ok = xb.next_to())
                {
                    edges.push_back({{"from", ea_hex(xb.from)}, {"to", ea_hex(cur)}, {"type", xb.iscode ? "code" : "data"}});
                    if (!visited.count(xb.from)) q.push({xb.from, depth + 1});
                }
            }
        }

        return {{"nodes", nodes}, {"edges", edges}};
    });

    // ---- analyze_component ----
    // Analyze a group of related functions as a component
    // params: {addresses: [string]}
    dispatcher.register_command("analyze_component", [](const json& params) -> json {
        auto addrs = params.at("addresses");

        json func_summaries = json::array();
        json internal_edges = json::array();
        std::set<ea_t> component_eas;

        // Collect component function addresses
        for (auto& a : addrs)
        {
            ea_t ea = parse_ea(a);
            func_t* f = get_func(ea);
            if (f) component_eas.insert(f->start_ea);
        }

        // Analyze each function
        for (ea_t fea : component_eas)
        {
            func_t* f = get_func(fea);
            if (!f) continue;

            qstring name;
            get_func_name(&name, f->start_ea);

            // Count callers/callees within component
            int internal_callers = 0, external_callers = 0;
            json callees_list = json::array();
            std::set<ea_t> seen_callees;

            // Callers
            xrefblk_t xb;
            for (bool ok = xb.first_to(f->start_ea, XREF_ALL); ok; ok = xb.next_to())
            {
                if (!xb.iscode) continue;
                func_t* caller = get_func(xb.from);
                if (!caller) continue;
                if (component_eas.count(caller->start_ea))
                    internal_callers++;
                else
                    external_callers++;
            }

            // Callees
            ea_t curr = f->start_ea;
            while (curr < f->end_ea && curr != BADADDR)
            {
                xrefblk_t xb2;
                for (bool ok = xb2.first_from(curr, XREF_FAR); ok; ok = xb2.next_from())
                {
                    if (!xb2.iscode) continue;
                    func_t* callee = get_func(xb2.to);
                    if (!callee || seen_callees.count(callee->start_ea)) continue;
                    seen_callees.insert(callee->start_ea);

                    qstring cname;
                    get_func_name(&cname, callee->start_ea);
                    bool internal = component_eas.count(callee->start_ea) > 0;

                    callees_list.push_back({
                        {"ea", ea_hex(callee->start_ea)}, {"name", cname.c_str()},
                        {"internal", internal},
                    });

                    if (internal)
                    {
                        internal_edges.push_back({
                            {"from", ea_hex(f->start_ea)}, {"to", ea_hex(callee->start_ea)},
                        });
                    }
                }
                curr = next_head(curr, f->end_ea);
            }

            func_summaries.push_back({
                {"ea", ea_hex(f->start_ea)},
                {"name", name.c_str()},
                {"size", (size_t)(f->end_ea - f->start_ea)},
                {"internal_callers", internal_callers},
                {"external_callers", external_callers},
                {"callees", callees_list},
            });
        }

        return {
            {"functions", func_summaries},
            {"internal_call_graph", internal_edges},
            {"component_size", component_eas.size()},
        };
    });

    // ---- diff_before_after ----
    // Apply an edit (rename/set_type/comment) and show before/after decompilation
    // params: {ea: string, action: "rename"|"set_type"|"set_comment", value: string}
    dispatcher.register_command("diff_before_after", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
        std::string action = params.at("action").get<std::string>();
        std::string value = params.at("value").get<std::string>();

        func_t* f = get_func(ea);
        if (!f)
            throw std::runtime_error("No function containing address");

        if (!init_hexrays_plugin())
            throw std::runtime_error("Hex-Rays required for diff");

        // Decompile BEFORE
        auto decompile_to_string = [](func_t* f) -> std::string {
            hexrays_failure_t hf;
            cfuncptr_t cfunc = decompile(f, &hf);
            if (!cfunc) return "(decompile failed)";
            const strvec_t& sv = cfunc->get_pseudocode();
            std::string result;
            for (size_t i = 0; i < sv.size(); i++)
            {
                qstring clean;
                tag_remove(&clean, sv[i].line);
                result += clean.c_str();
                result += "\n";
            }
            return result;
        };

        std::string before = decompile_to_string(f);

        // Apply action
        bool applied = false;
        if (action == "rename")
        {
            applied = set_name(ea, value.c_str(), SN_CHECK);
        }
        else if (action == "set_type")
        {
            tinfo_t tif;
            if (parse_decl(&tif, nullptr, nullptr, value.c_str(), PT_SIL))
                applied = apply_tinfo(ea, tif, TINFO_DEFINITE);
        }
        else if (action == "set_comment")
        {
            applied = set_cmt(ea, value.c_str(), false);
        }
        else
        {
            throw std::runtime_error("Unknown action: " + action);
        }

        // Decompile AFTER
        std::string after = decompile_to_string(f);

        return {
            {"ea", ea_hex(ea)},
            {"action", action},
            {"value", value},
            {"applied", applied},
            {"before", before},
            {"after", after},
            {"changed", before != after},
        };
    });
}
