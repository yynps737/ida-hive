// The IDA SDK macro-redefines snprintf/fprintf/stderr, so these helpers wrap the
// q-prefixed SDK equivalents instead.

#pragma once

#include <ida.hpp>
#include <pro.h>
#include <name.hpp>
#include <entry.hpp>

#include <string>
#include <stdexcept>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// The launch path, and the default save target. The live database is usually a
// private copy in a temp dir, not the path the caller gave. Defined in worker.cpp.
extern std::string g_original_input;

// This worker's private database directory, empty for in-place manual runs.
// Defined in worker.cpp.
extern std::string g_db_dir;

// Selects database over raw-binary handling. The comparison is case-insensitive so
// an uppercase .I64 is not mistaken for a raw binary.
inline bool has_db_extension(const std::string& p)
{
    if (p.size() < 4) return false;
    std::string e = p.substr(p.size() - 4);
    for (char& c : e) if (c >= 'A' && c <= 'Z') c += 32;
    return e == ".i64" || e == ".idb";
}

inline std::string ea_hex(ea_t ea)
{
    char buf[32];
    qsnprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)ea);
    return buf;
}

// stderr only; stdout carries the protocol.
#define LOG(fmt, ...) qeprintf("[worker] " fmt "\n", ##__VA_ARGS__)

// Resolves a symbol name, matching lookup_func's tiers so decompile(ea="malloc")
// works wherever lookup_func("malloc") does. Returns BADADDR on no match.
//
// The tiers are tried in the order below, strongest first. Many libc names are
// reachable only through a weaker one: the address at 'malloc' may carry the
// primary name '__libc_malloc', and an alias like 'printf' may be registered
// nowhere.
inline ea_t resolve_name_ea(const std::string& s)
{
    // Primary/registered name.
    ea_t e = get_name_ea(BADADDR, s.c_str());
    if (e != BADADDR)
        return e;

    // glibc stacks decorations arbitrarily (free -> __libc_free -> __GI___libc_free),
    // so the combinations cannot be enumerated. Peeling instead terminates on any depth.
    auto matches_decorated = [&s](const char* name) -> bool {
        if (name == nullptr) return false;
        std::string cur = name;
        if (cur == s) return true;
        static const char* const pfx[] = { "__GI_", "__libc_", "__", "_" };
        bool stripped = true;
        while (stripped)
        {
            stripped = false;
            for (const char* p : pfx)
            {
                size_t plen = qstrlen(p);
                if (cur.size() > plen && cur.compare(0, plen, p) == 0)
                {
                    cur.erase(0, plen);
                    if (cur == s) return true;
                    stripped = true;
                    break;
                }
            }
        }
        return false;
    };

    // Name list, exact on the raw or demangled name. A decoration-stripped hit is
    // only remembered here, never returned, so an exact match later still wins.
    size_t n = get_nlist_size();
    ea_t decorated_hit = BADADDR;
    for (size_t i = 0; i < n; i++)
    {
        ea_t a = get_nlist_ea(i);
        const char* nm = get_nlist_name(i);
        if (nm != nullptr && s == nm)
            return a;
        qstring sn = get_short_name(a);
        if (!sn.empty() && s == sn.c_str())
            return a;
        if (decorated_hit == BADADDR && matches_decorated(nm))
            decorated_hit = a;
    }

    // Entry-point table, exact on the export name.
    size_t eq = get_entry_qty();
    for (size_t i = 0; i < eq; i++)
    {
        uval_t ord = get_entry_ordinal(i);
        qstring en;
        if (get_entry_name(&en, ord) > 0 && !en.empty() && s == en.c_str())
        {
            ea_t a = get_entry(ord);
            if (a != BADADDR)
                return a;
        }
    }

    // Weakest tier: the decoration-stripped hit held back above.
    if (decorated_hit != BADADDR)
        return decorated_hit;

    return BADADDR;
}

// Accepts an integer, a numeric string, or a symbol name.
inline ea_t parse_ea(const json& val)
{
    if (val.is_string())
    {
        std::string s = val.get<std::string>();
        try
        {
            // Base 0: "0x" reads as hex, a leading "0" as octal, otherwise decimal.
            return (ea_t)std::stoull(s, nullptr, 0);
        }
        catch (...)
        {
            ea_t e = resolve_name_ea(s);
            if (e == BADADDR)
                throw std::runtime_error("Could not resolve '" + s + "' as an address or name");
            return e;
        }
    }
    return (ea_t)val.get<uint64_t>();
}
