// cmd_memory.cpp - Memory read/write commands
#include "../pch.h"

#include <ida.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <typeinf.hpp>

#include "cmd_memory.h"
#include "../util.h"

void register_memory_commands(CommandDispatcher& dispatcher)
{
    // ---- get_bytes ----
    dispatcher.register_command("get_bytes", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
        size_t size = params.at("size").get<size_t>();

        if (size > 0x10000)
            throw std::runtime_error("Size too large (max 64KB)");

        std::vector<uint8_t> buf(size);
        ssize_t got = get_bytes(buf.data(), size, ea);
        if (got < 0)
            throw std::runtime_error("Failed to read bytes");

        // Return as hex string
        std::string hex;
        hex.reserve(got * 2);
        for (ssize_t i = 0; i < got; i++)
        {
            char h[4];
            qsnprintf(h, sizeof(h), "%02X", buf[i]);
            hex += h;
        }

        return {{"ea", ea_hex(ea)}, {"hex", hex}, {"size", got}};
    });

    // ---- patch_bytes ----
    dispatcher.register_command("patch_bytes", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
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
    });

    // ---- get_string ----
    dispatcher.register_command("get_string", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));

        size_t len = get_max_strlit_length(ea, STRTYPE_C);
        if (len == 0)
            throw std::runtime_error("No string at given address");

        std::vector<uint8_t> buf(len + 1, 0);
        get_bytes(buf.data(), len, ea);

        return {
            {"ea",     ea_hex(ea)},
            {"string", std::string(reinterpret_cast<char*>(buf.data()))},
            {"length", len},
        };
    });

    // ---- get_int ----
    // Read an integer value at address
    // params: {ea: string, size?: int}  (size: 1/2/4/8 bytes)
    dispatcher.register_command("get_int", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
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
    });

    // ---- put_int ----
    // Write an integer value at address
    // params: {ea: string, value: int|string, size?: int}
    dispatcher.register_command("put_int", [](const json& params) -> json {
        ea_t ea = parse_ea(params.at("ea"));
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
    });

    // ---- get_global_value ----
    // Read a global variable by name or address
    // params: {target: string}
    dispatcher.register_command("get_global_value", [](const json& params) -> json {
        std::string target = params.at("target").get<std::string>();

        ea_t ea = BADADDR;
        try { ea = (ea_t)std::stoull(target, nullptr, 0); } catch (...) {}
        if (ea == BADADDR)
            ea = get_name_ea(BADADDR, target.c_str());
        if (ea == BADADDR)
            throw std::runtime_error("Not found: " + target);

        // Get type info to determine size
        tinfo_t tif;
        asize_t vsize = 8; // default
        if (get_tinfo(&tif, ea))
            vsize = tif.get_size();
        if (vsize == 0 || vsize == BADSIZE) vsize = 8;
        if (vsize > 64) vsize = 64;

        // Read bytes
        std::vector<uint8_t> buf(vsize);
        get_bytes(buf.data(), vsize, ea);

        std::string hex;
        for (size_t i = 0; i < vsize; i++)
        {
            char h[4];
            qsnprintf(h, sizeof(h), "%02X", buf[i]);
            hex += h;
        }

        // Read as integer if small enough
        uint64_t int_val = 0;
        if (vsize <= 8)
        {
            for (size_t i = 0; i < vsize; i++)
                int_val |= ((uint64_t)buf[i]) << (i * 8);
        }

        qstring name;
        get_ea_name(&name, ea);

        qstring type_str;
        if (tif.is_correct())
            tif.print(&type_str);

        return {
            {"ea", ea_hex(ea)},
            {"name", name.c_str()},
            {"type", type_str.c_str()},
            {"size", vsize},
            {"hex", hex},
            {"value", vsize <= 8 ? json(int_val) : json(nullptr)},
        };
    });
}
