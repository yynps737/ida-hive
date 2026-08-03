#include "ida_hive/pch.hpp"

#include <ida.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <typeinf.hpp>

#include "ida_hive/commands.hpp"
#include "ida_hive/util.hpp"
#include "ida_hive/params.hpp"

namespace ida_hive {
namespace {

json cmd_get_bytes(const json &params)
{
    ea_t ea = require_ea(params);

    // Read signed: a negative size taken as size_t becomes an enormous positive one
    // and gets reported as exceeding the cap, which names the wrong problem.
    const int64_t requested = params.at("size").get<int64_t>();
    if (requested < 0)
        throw std::runtime_error("Size must not be negative");
    if (requested > 0x10000)
        throw std::runtime_error("Size too large (max 64KB)");

    const size_t size = (size_t)requested;
    std::vector<uint8_t> buf(size);
    const size_t got = read_available(buf.data(), size, ea);

    // Stopping short is normal — .bss carries no stored bytes — but an unannounced
    // short answer reads as though the range were that small.
    json out = {{"ea", ea_hex(ea)}, {"hex", to_hex(buf.data(), got)}, {"size", got}};
    if (got < size)
    {
        out["requested"] = size;
        out["truncated"] = true;
        out["reason"]    = got == 0 ? "no stored bytes at this address"
                                    : "range reaches bytes with no stored value";
    }
    return out;
}

json cmd_patch_bytes(const json &params)
{
    ea_t ea = require_ea(params);
    std::string hex = params.at("hex").get<std::string>();

    if (hex.size() % 2 != 0)
        throw std::runtime_error("Hex string must be even length");

    size_t size = hex.size() / 2;
    std::vector<uint8_t> buf(size);

    for (size_t i = 0; i < size; i++)
    {
        auto byte_str = hex.substr(i * 2, 2);
        buf[i] = (uint8_t)strtoul(byte_str.c_str(), nullptr, 16);
    }

    patch_bytes(ea, buf.data(), size);

    return {{"ea", ea_hex(ea)}, {"patched", size}};
}

json cmd_get_string(const json &params)
{
    ea_t ea = require_ea(params);

    size_t len = get_max_strlit_length(ea, STRTYPE_C);
    if (len == 0)
        throw std::runtime_error("No string at given address");

    std::vector<uint8_t> buf(len + 1, 0);
    const size_t got = read_available(buf.data(), len, ea);

    json out = {
        {"ea",     ea_hex(ea)},
        {"string", std::string(reinterpret_cast<char*>(buf.data()))},
        {"length", len},
    };
    if (got < len)
        out["truncated"] = true;   // The tail has no stored bytes, not a shorter string.
    return out;
}

json cmd_get_int(const json &params)
{
    ea_t ea = require_ea(params);
    int size = params.value("size", 4);

    uint64_t val = 0;
    switch (size)
    {
        case 1: val = get_byte(ea); break;
        case 2: val = get_word(ea); break;
        case 4: val = get_dword(ea); break;
        case 8: val = get_qword(ea); break;
        default: throw std::runtime_error("Size must be 1, 2, 4, or 8");
    }

    return {{"ea", ea_hex(ea)}, {"value", val}, {"hex", ea_hex(val)}, {"size", size}};
}

json cmd_put_int(const json &params)
{
    ea_t ea = require_ea(params);
    int size = params.value("size", 4);

    uint64_t val;
    if (params["value"].is_string())
        val = std::stoull(params["value"].get<std::string>(), nullptr, 0);
    else
        val = params["value"].get<uint64_t>();

    switch (size)
    {
        case 1: patch_byte(ea, (uint8_t)val); break;
        case 2: patch_word(ea, (uint16_t)val); break;
        case 4: patch_dword(ea, (uint32_t)val); break;
        case 8: patch_qword(ea, val); break;
        default: throw std::runtime_error("Size must be 1, 2, 4, or 8");
    }

    return {{"ea", ea_hex(ea)}, {"value", val}, {"size", size}, {"success", true}};
}

json cmd_get_global_value(const json &params)
{
    std::string target = params.at("target").get<std::string>();

    ea_t ea = BADADDR;
    try { ea = (ea_t)std::stoull(target, nullptr, 0); } catch (...) {}
    if (ea == BADADDR)
        ea = get_name_ea(BADADDR, target.c_str());
    if (ea == BADADDR)
        throw std::runtime_error("Not found: " + target);

    tinfo_t tif;
    asize_t vsize = 0;
    if (get_tinfo(&tif, ea))
        vsize = tif.get_size();
    if (vsize == 0 || vsize == BADSIZE)
    {
        // Falls back to the item's own extent when the type carries no size.
        asize_t isz = get_item_size(ea);
        vsize = (isz != 0) ? isz : 8;
    }
    if (vsize > 64) vsize = 64;

    std::vector<uint8_t> buf(vsize);
    const size_t got = read_available(buf.data(), vsize, ea);

    // An uninitialized global has no stored value. Reporting the zero-filled buffer
    // would answer "0" for a variable the database says nothing about.
    if (got == 0)
        return {
            {"ea",        ea_hex(ea)},
            {"size",      vsize},
            {"hex",       nullptr},
            {"value",     nullptr},
            {"has_value", false},
            {"reason",    "no stored bytes at this address"},
        };

    const std::string hex = to_hex(buf.data(), got);

    // A value needs every byte of the variable; a partial read cannot produce one.
    const bool whole = got == vsize;
    uint64_t int_val = 0;
    bool is_signed = false;
    if (whole && vsize <= 8)
    {
        for (size_t i = 0; i < vsize; i++)
            int_val |= ((uint64_t)buf[i]) << (i * 8);

        // The variable's own type decides how its bytes read. Reporting the unsigned
        // interpretation of a signed type contradicts the `type` field beside it:
        // an int32_t holding 0xFFFFFFFE is -2, never 4294967294.
        is_signed = tif.is_correct() && tif.is_signed();
        if (is_signed && vsize < 8)
        {
            const uint64_t sign_bit = 1ULL << (vsize * 8 - 1);
            if ((int_val & sign_bit) != 0)
                int_val |= ~(sign_bit * 2 - 1);
        }
    }

    qstring name;
    get_ea_name(&name, ea);

    qstring type_str;
    if (tif.is_correct())
        tif.print(&type_str);

    json out = {
        {"ea",        ea_hex(ea)},
        {"name",      name.c_str()},
        {"type",      type_str.c_str()},
        {"size",      vsize},
        {"hex",       hex},
        {"value",     whole && vsize <= 8
                          ? (is_signed ? json((int64_t)int_val) : json(int_val))
                          : json(nullptr)},
        {"has_value", true},
    };
    if (!whole)
    {
        out["stored"]    = got;
        out["truncated"] = true;
    }
    return out;
}

const command_entry_t kCommands[] = {
    { "get_bytes",        cmd_get_bytes },
    { "patch_bytes",      cmd_patch_bytes },
    { "get_string",       cmd_get_string },
    { "get_int",          cmd_get_int },
    { "put_int",          cmd_put_int },
    { "get_global_value", cmd_get_global_value },
};

}  // namespace

void register_memory_commands(CommandDispatcher &dispatcher)
{
    dispatcher.register_table(kCommands);
}

}  // namespace ida_hive
