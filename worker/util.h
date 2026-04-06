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
