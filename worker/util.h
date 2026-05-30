// util.h - IDA-safe utility functions
//
// IDA SDK redefines snprintf/fprintf/stderr via macros.
// Use these helpers instead.

#pragma once

#include <ida.hpp>
#include <pro.h>
#include <name.hpp>
#include <entry.hpp>

#include <string>
#include <stdexcept>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// Original input path the worker was launched with (defined in worker.cpp).
// Used as the default save location, since the live database may be a private
// copy in a temp dir rather than the path the AI actually provided.
extern std::string g_original_input;

// This worker's private database directory (defined in worker.cpp). Empty for
// legacy in-place manual runs. Used to derive a unique temp name when saving.
extern std::string g_db_dir;

// True if the path ends with a case-INSENSITIVE .i64/.idb extension. Used to
// decide raw-binary vs database handling; case-insensitive so an uppercase
// .I64 on a case-insensitive filesystem still takes the database path and is
// not mis-handled as a raw binary.
inline bool has_db_extension(const std::string& p)
{
    if (p.size() < 4) return false;
    std::string e = p.substr(p.size() - 4);
    for (char& c : e) if (c >= 'A' && c <= 'Z') c += 32;
    return e == ".i64" || e == ".idb";
}

// Format ea_t as hex string "0x..."
inline std::string ea_hex(ea_t ea)
{
    char buf[32];
    qsnprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)ea);
    return buf;
}

// Log to stderr (IDA-safe)
#define LOG(fmt, ...) qeprintf("[worker] " fmt "\n", ##__VA_ARGS__)

// Resolve a symbol name to an address using the same broad set of tiers as
// lookup_func, so decompile(ea="malloc") works wherever lookup_func("malloc")
// does. Returns BADADDR if nothing matches.
//
// Many libc/exported names are reachable only via a non-primary tier: the
// address at 'malloc' may carry the primary name '__libc_malloc', and weak
// aliases like 'printf' may not be the registered name at all. Tiers are tried
// in priority order so a primary-name match always wins when present.
inline ea_t resolve_name_ea(const std::string& s)
{
    // 2. Primary/registered name.
    ea_t e = get_name_ea(BADADDR, s.c_str());
    if (e != BADADDR)
        return e;

    // Helper: does 'name' equal 's' after stripping any stack of known glibc
    // decoration prefixes? glibc exports stack decorations arbitrarily, e.g.
    // free -> __libc_free -> __GI___libc_free, so a fixed prefix list cannot be
    // enumerated. Instead, peel known prefixes off 'name' and check for 's'.
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

    // 3. Scan the name list: exact match on the raw or demangled/short name,
    //    then a decoration-stripped match (so 'free' resolves to the address
    //    whose primary name is '__GI___libc_free', etc.).
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

    // 4. Entry-point table: exact match on the export name.
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

    // 5. Fall back to a decoration-stripped name-list hit (lower priority than
    //    any exact/entry match above).
    if (decorated_hit != BADADDR)
        return decorated_hit;

    return BADADDR;
}

// Parse address from JSON value (hex string or integer)
inline ea_t parse_ea(const json& val)
{
    if (val.is_string())
    {
        std::string s = val.get<std::string>();
        try
        {
            // 1. Numeric fast-path (hex/decimal).
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
