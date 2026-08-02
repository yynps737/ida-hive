// Call-edge classification, shared by every tool that walks callees.
//
// Reading xrefs naively counts ordinary fall-through and intra-function jumps as
// calls, which produces spurious self-edges and inflated callee lists. The rules
// live here once so all tools agree.

#pragma once

#include <ida.hpp>
#include <funcs.hpp>
#include <xref.hpp>
#include <bytes.hpp>
#include <nalt.hpp>

#include <set>
#include <vector>
#include <string>

namespace ida_hive {

// A resolved call edge: the callee entry, plus how control reaches it.
struct call_edge_t
{
    ea_t callee_ea;
    bool via_jump;      // tail call rather than a direct CALL
};

// True when this code xref is a call or a jump, i.e. not fall-through (fl_F).
inline bool is_branch_xref(const xrefblk_t &xb, bool *is_jump)
{
    bool call = xb.type == fl_CN || xb.type == fl_CF;
    bool jump = xb.type == fl_JN || xb.type == fl_JF;
    *is_jump = jump;
    return call || jump;
}

// Collects the functions called from `range`, deduplicated and in first-seen order.
//
// A jump qualifies only when it lands on another function's entry, which is a tail
// call; mid-function targets are internal control flow. Genuine self-recursion is
// kept, since a direct call to one's own entry is a real edge.
inline std::vector<call_edge_t> collect_callees(ea_t start, ea_t end)
{
    std::vector<call_edge_t> out;
    std::set<ea_t> seen;

    for (ea_t curr = start; curr < end && curr != BADADDR; curr = next_head(curr, end))
    {
        xrefblk_t xb;
        for (bool ok = xb.first_from(curr, XREF_ALL); ok; ok = xb.next_from())
        {
            if (!xb.iscode)
                continue;

            bool is_jump = false;
            if (!is_branch_xref(xb, &is_jump))
                continue;

            func_t *callee = get_func(xb.to);
            if (callee == nullptr)
                continue;
            if (is_jump && xb.to != callee->start_ea)
                continue;

            if (seen.insert(callee->start_ea).second)
                out.push_back({ callee->start_ea, is_jump });
        }
    }
    return out;
}

// A string literal referenced from code.
struct string_ref_t
{
    ea_t        ea;
    std::string text;
};

// Collects the string literals `range` points at, in first-seen order.
//
// Walks the data xrefs that collect_callees skips, so the two are complementary
// halves of the same instruction sweep.
inline std::vector<string_ref_t> collect_string_refs(ea_t start, ea_t end, size_t limit)
{
    std::vector<string_ref_t> out;
    std::set<ea_t> seen;

    for (ea_t curr = start; curr < end && curr != BADADDR && out.size() < limit;
         curr = next_head(curr, end))
    {
        xrefblk_t xb;
        for (bool ok = xb.first_from(curr, XREF_ALL); ok && out.size() < limit; ok = xb.next_from())
        {
            if (xb.iscode)
                continue;

            size_t len = get_max_strlit_length(xb.to, STRTYPE_C);
            if (len <= 2 || !seen.insert(xb.to).second)
                continue;

            std::vector<uint8_t> buf(len + 1, 0);
            get_bytes(buf.data(), len, xb.to);
            out.push_back({ xb.to, std::string(reinterpret_cast<char *>(buf.data())) });
        }
    }
    return out;
}

// Counts code xrefs targeting `ea`, which is the caller count for a function entry.
inline int count_callers(ea_t ea)
{
    int n = 0;
    xrefblk_t xb;
    for (bool ok = xb.first_to(ea, XREF_ALL); ok; ok = xb.next_to())
        if (xb.iscode)
            n++;
    return n;
}

}  // namespace ida_hive
