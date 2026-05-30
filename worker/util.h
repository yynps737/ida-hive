// util.h - IDA-safe utility functions
//
// IDA SDK redefines snprintf/fprintf/stderr via macros.
// Use these helpers instead.

#pragma once

#include <ida.hpp>
#include <pro.h>

#include <string>
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

// Parse address from JSON value (hex string or integer)
inline ea_t parse_ea(const json& val)
{
    if (val.is_string())
    {
        std::string s = val.get<std::string>();
        return (ea_t)std::stoull(s, nullptr, 0);
    }
    return (ea_t)val.get<uint64_t>();
}
