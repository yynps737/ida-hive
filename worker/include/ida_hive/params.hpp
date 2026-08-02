// Request-parameter accessors shared by every command handler.
//
// Handlers state their preconditions by calling these instead of re-deriving them:
// each throws std::runtime_error with a caller-facing message, which the dispatcher
// turns into an {"error"} reply.

#pragma once

#include <ida.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <hexrays.hpp>

#include <string>
#include <stdexcept>
#include <nlohmann/json.hpp>

#include "ida_hive/util.hpp"

using json = nlohmann::json;


namespace ida_hive {
// Required address, accepting a hex string, an integer, or a symbol name.
inline ea_t require_ea(const json &params, const char *key = "ea")
{
    if (!params.contains(key))
        throw std::runtime_error(std::string("missing required parameter '") + key + "'");
    return parse_ea(params.at(key));
}

// Required address that must resolve to a function.
inline func_t &require_func(const json &params, const char *key = "ea")
{
    ea_t ea = require_ea(params, key);
    func_t *f = get_func(ea);
    if (f == nullptr)
        throw std::runtime_error("no function at " + ea_hex(ea));
    return *f;
}

inline std::string require_str(const json &params, const char *key)
{
    if (!params.contains(key) || !params.at(key).is_string())
        throw std::runtime_error(std::string("missing required string parameter '") + key + "'");
    return params.at(key).get<std::string>();
}

inline std::string opt_str(const json &params, const char *key, const char *dflt = "")
{
    return params.contains(key) && params.at(key).is_string()
         ? params.at(key).get<std::string>()
         : std::string(dflt);
}

// Result limits are clamped rather than rejected: an over-large request should
// return a capped page, not an error.
inline size_t opt_limit(const json &params, size_t dflt, size_t cap = 10000)
{
    size_t v = params.value("limit", dflt);
    return v > cap ? cap : v;
}

inline size_t opt_size(const json &params, const char *key, size_t dflt)
{
    return params.value(key, dflt);
}

// The decompiler is optional at runtime, so every tool that needs it must say so
// before touching a cfunc_t.
inline cfuncptr_t require_decompiled(func_t &f)
{
    if (!init_hexrays_plugin())
        throw std::runtime_error("Hex-Rays decompiler is not available");

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(&f, &hf);
    if (cfunc == nullptr)
        throw std::runtime_error(hf.desc().empty()
                                 ? std::string("decompilation failed")
                                 : std::string(hf.desc().c_str()));
    return cfunc;
}

// Function name as a std::string, empty when the address has none.
inline std::string func_name_of(ea_t ea)
{
    qstring nm;
    get_func_name(&nm, ea);
    return nm.empty() ? std::string() : std::string(nm.c_str());
}

}  // namespace ida_hive
