// cmd_analysis.cpp - Analysis commands: decompile, disasm, xrefs_to, callees
#include "../pch.h"

#include <ida.hpp>
#include <idp.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <lines.hpp>
#include <ua.hpp>
#include <xref.hpp>
#include <hexrays.hpp>

#include "cmd_analysis.h"
#include "../util.h"

static bool s_hexrays_available = false;
static bool s_hexrays_init_tried = false;

void register_analysis_commands(CommandDispatcher& dispatcher)
{
    // ---- decompile ----
    dispatcher.register_command("decompile", [](const json& params) -> json {
        if (!s_hexrays_init_tried)
        {
            s_hexrays_init_tried = true;
            s_hexrays_available = init_hexrays_plugin();
            LOG("Hex-Rays init: %s", s_hexrays_available ? "OK" : "FAILED");
        }

        if (!s_hexrays_available)
            throw std::runtime_error("Hex-Rays decompiler not available");

        ea_t ea = parse_ea(params.at("ea"));
        func_t* f = get_func(ea);
        if (!f)
            throw std::runtime_error("No function at given address");

        hexrays_failure_t hf;
        cfuncptr_t cfunc = decompile(f, &hf);
        if (!cfunc)
            throw std::runtime_error(std::string("Decompilation failed: ") + hf.desc().c_str());

        const strvec_t& sv = cfunc->get_pseudocode();
        std::string pseudocode;
        for (size_t i = 0; i < sv.size(); i++)
        {
            qstring clean;
            tag_remove(&clean, sv[i].line);
            pseudocode += clean.c_str();
            pseudocode += "\n";
        }

        qstring func_name;
        get_func_name(&func_name, f->start_ea);

        return {
            {"ea",         ea_hex(f->start_ea)},
            {"name",       func_name.c_str()},
            {"pseudocode", pseudocode},
        };
    });

    // ---- disasm ----
    dispatcher.register_command("disasm", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
        size_t count = params.value("count", 50);

        func_t* f = get_func(ea);
        ea_t start = f ? f->start_ea : ea;
        ea_t end   = f ? f->end_ea   : BADADDR;

        json lines = json::array();
        ea_t curr = start;

        for (size_t i = 0; i < count && curr < end && curr != BADADDR; i++)
        {
            qstring buf;
            generate_disasm_line(&buf, curr, GENDSM_REMOVE_TAGS);

            insn_t insn;
            int insn_len = decode_insn(&insn, curr);

            lines.push_back({
                {"ea",   ea_hex(curr)},
                {"text", buf.c_str()},
                {"size", insn_len > 0 ? insn_len : 1},
            });

            curr = insn_len > 0 ? curr + insn_len : next_head(curr, end);
        }

        qstring func_name;
        if (f) get_func_name(&func_name, f->start_ea);

        return {
            {"ea",    ea_hex(start)},
            {"name",  f ? func_name.c_str() : ""},
            {"lines", lines},
        };
    });

    // ---- xrefs_to ----
    dispatcher.register_command("xrefs_to", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));

        json refs = json::array();
        xrefblk_t xb;
        for (bool ok = xb.first_to(ea, XREF_ALL); ok; ok = xb.next_to())
        {
            qstring from_name;
            func_t* from_func = get_func(xb.from);
            if (from_func)
                get_func_name(&from_name, from_func->start_ea);

            refs.push_back({
                {"from", ea_hex(xb.from)},
                {"type", xb.iscode ? "code" : "data"},
                {"func", from_func ? from_name.c_str() : ""},
            });
        }

        return {{"ea", ea_hex(ea)}, {"xrefs", refs}};
    });

    // ---- xrefs_from ----
    dispatcher.register_command("xrefs_from", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));

        json refs = json::array();
        xrefblk_t xb;
        for (bool ok = xb.first_from(ea, XREF_ALL); ok; ok = xb.next_from())
        {
            qstring to_name;
            func_t* to_func = get_func(xb.to);
            if (to_func)
                get_func_name(&to_name, to_func->start_ea);

            refs.push_back({
                {"to",   ea_hex(xb.to)},
                {"type", xb.iscode ? "code" : "data"},
                {"func", to_func ? to_name.c_str() : ""},
            });
        }

        return {{"ea", ea_hex(ea)}, {"xrefs", refs}};
    });

    // ---- callees ----
    dispatcher.register_command("callees", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
        func_t* f = get_func(ea);
        if (!f)
            throw std::runtime_error("No function at given address");

        json callees = json::array();
        ea_t curr = f->start_ea;
        while (curr < f->end_ea && curr != BADADDR)
        {
            xrefblk_t xb;
            for (bool ok = xb.first_from(curr, XREF_FAR); ok; ok = xb.next_from())
            {
                if (!xb.iscode) continue;
                func_t* target = get_func(xb.to);
                if (!target) continue;

                qstring callee_name;
                get_func_name(&callee_name, target->start_ea);

                callees.push_back({
                    {"ea",   ea_hex(target->start_ea)},
                    {"name", callee_name.c_str()},
                });
            }
            curr = next_head(curr, f->end_ea);
        }

        return {{"callees", callees}};
    });

    // ---- xref_query ----
    // Unified xref query with direction and type filters
    // params: {ea: string, direction?: "to"|"from"|"both", code_only?: bool, limit?: int}
    dispatcher.register_command("xref_query", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
        std::string direction = params.value("direction", std::string("both"));
        bool code_only = params.value("code_only", false);
        size_t limit = params.value("limit", 100);

        json refs = json::array();

        if (direction == "to" || direction == "both")
        {
            xrefblk_t xb;
            for (bool ok = xb.first_to(ea, XREF_ALL); ok && refs.size() < limit; ok = xb.next_to())
            {
                if (code_only && !xb.iscode) continue;
                qstring fname;
                func_t* ff = get_func(xb.from);
                if (ff) get_func_name(&fname, ff->start_ea);
                refs.push_back({
                    {"from", ea_hex(xb.from)}, {"to", ea_hex(ea)},
                    {"direction", "to"}, {"type", xb.iscode ? "code" : "data"},
                    {"func", ff ? fname.c_str() : ""},
                });
            }
        }

        if (direction == "from" || direction == "both")
        {
            xrefblk_t xb;
            for (bool ok = xb.first_from(ea, XREF_ALL); ok && refs.size() < limit; ok = xb.next_from())
            {
                if (code_only && !xb.iscode) continue;
                qstring fname;
                func_t* ff = get_func(xb.to);
                if (ff) get_func_name(&fname, ff->start_ea);
                refs.push_back({
                    {"from", ea_hex(ea)}, {"to", ea_hex(xb.to)},
                    {"direction", "from"}, {"type", xb.iscode ? "code" : "data"},
                    {"func", ff ? fname.c_str() : ""},
                });
            }
        }

        return {{"ea", ea_hex(ea)}, {"xrefs", refs}, {"count", refs.size()}};
    });

    // ---- xrefs_to_field ----
    // Find references to a specific struct field offset within functions
    // params: {ea: string, field_offset: int, limit?: int}
    // Searches disassembly for operands referencing [reg+field_offset]
    dispatcher.register_command("xrefs_to_field", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
        int field_offset = params.at("field_offset").get<int>();
        size_t limit = params.value("limit", 50);

        // Search within the function for references to the offset
        func_t* f = get_func(ea);
        if (!f) throw std::runtime_error("No function at address");

        json refs = json::array();
        ea_t curr = f->start_ea;
        insn_t insn;

        while (curr < f->end_ea && curr != BADADDR && refs.size() < limit)
        {
            int len = decode_insn(&insn, curr);
            if (len <= 0) { curr = next_head(curr, f->end_ea); continue; }

            // Check operands for displacement matching field_offset
            for (int op = 0; op < UA_MAXOP; op++)
            {
                if (insn.ops[op].type == o_void) break;
                if (insn.ops[op].type == o_displ && insn.ops[op].addr == (ea_t)field_offset)
                {
                    qstring dline;
                    generate_disasm_line(&dline, curr, GENDSM_REMOVE_TAGS);
                    refs.push_back({
                        {"ea", ea_hex(curr)}, {"disasm", dline.c_str()},
                    });
                    break;
                }
            }
            curr += len;
        }

        return {{"ea", ea_hex(f->start_ea)}, {"field_offset", field_offset}, {"refs", refs}};
    });

    // ---- analyze_batch ----
    // Batch analysis: decompile multiple functions at once
    // params: {addresses: [string]}
    dispatcher.register_command("analyze_batch", [](const json& params) -> json {
        auto addrs = params.at("addresses");
        bool has_hexrays = init_hexrays_plugin();

        json results = json::array();
        for (auto& addr_val : addrs)
        {
            ea_t ea = parse_ea(addr_val);
            func_t* f = get_func(ea);
            if (!f)
            {
                results.push_back({{"ea", ea_hex(ea)}, {"error", "No function at address"}});
                continue;
            }

            qstring name;
            get_func_name(&name, f->start_ea);

            json entry = {
                {"ea", ea_hex(f->start_ea)},
                {"name", name.c_str()},
                {"size", (size_t)(f->end_ea - f->start_ea)},
            };

            // Decompile if available
            if (has_hexrays)
            {
                hexrays_failure_t hf;
                cfuncptr_t cfunc = decompile(f, &hf);
                if (cfunc)
                {
                    const strvec_t& sv = cfunc->get_pseudocode();
                    std::string pseudo;
                    for (size_t i = 0; i < sv.size(); i++)
                    {
                        qstring clean;
                        tag_remove(&clean, sv[i].line);
                        pseudo += clean.c_str();
                        pseudo += "\n";
                    }
                    entry["pseudocode"] = pseudo;
                }
                else
                {
                    entry["decompile_error"] = hf.desc().c_str();
                }
            }

            results.push_back(entry);
        }

        return {{"results", results}, {"count", results.size()}};
    });

    // ---- export_funcs ----
    // Export function info in JSON format
    // params: {addresses?: [string], limit?: int}
    dispatcher.register_command("export_funcs", [](const json& params) -> json {
        size_t limit = params.value("limit", 100);

        json funcs = json::array();

        if (params.contains("addresses"))
        {
            for (auto& addr_val : params["addresses"])
            {
                ea_t ea = parse_ea(addr_val);
                func_t* f = get_func(ea);
                if (!f) continue;

                qstring name;
                get_func_name(&name, f->start_ea);

                tinfo_t tif;
                qstring proto;
                if (get_tinfo(&tif, f->start_ea))
                    tif.print(&proto);

                funcs.push_back({
                    {"ea", ea_hex(f->start_ea)},
                    {"name", name.c_str()},
                    {"size", (size_t)(f->end_ea - f->start_ea)},
                    {"prototype", proto.c_str()},
                });
            }
        }
        else
        {
            size_t total = get_func_qty();
            for (size_t i = 0; i < total && funcs.size() < limit; i++)
            {
                func_t* f = getn_func(i);
                if (!f) continue;

                qstring name;
                get_func_name(&name, f->start_ea);

                tinfo_t tif;
                qstring proto;
                if (get_tinfo(&tif, f->start_ea))
                    tif.print(&proto);

                funcs.push_back({
                    {"ea", ea_hex(f->start_ea)},
                    {"name", name.c_str()},
                    {"size", (size_t)(f->end_ea - f->start_ea)},
                    {"prototype", proto.c_str()},
                });
            }
        }

        return {{"functions", funcs}, {"count", funcs.size()}};
    });
}
