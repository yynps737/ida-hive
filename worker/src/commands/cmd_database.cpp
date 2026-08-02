#include "ida_hive/pch.hpp"

#include <ida.hpp>
#include <netnode.hpp>
#include <srclang.hpp>
#include <undo.hpp>
#include <typeinf.hpp>

#include "ida_hive/commands.hpp"
#include "ida_hive/util.hpp"
#include "ida_hive/params.hpp"

namespace ida_hive {
namespace {

// Three subsystems that sit under the analysis rather than beside it.
//
// netnode is the key-value store the whole database is built on: every name,
// comment and type ultimately lives in one. Reading it reaches data that no typed
// API exposes — plugin state, loader metadata, anything a tool stashed away.
// Writing to the wrong node corrupts the database silently, with no diagnostic and
// no way back, so only named nodes the caller creates are writable here; the nodes
// IDA owns are read-only.
//
// srclang selects the parser behind declare_type, which is what makes a Swift or
// Go declaration parse as that language instead of as C.
//
// undo groups edits into revertible points.

// ---- netnode ----

// Names IDA's own storage so a caller can tell it apart from their own data.
// The list is not exhaustive; it covers the nodes worth recognising on sight.
const char *well_known_node(const char *name)
{
    if (name == nullptr || *name == '\0')
        return nullptr;
    if (qstrcmp(name, "$ vmapping") == 0)      return "loader memory map";
    if (qstrcmp(name, "$ segstrings") == 0)    return "segment names";
    if (qstrcmp(name, "$ fileregions") == 0)   return "file region map";
    if (qstrcmp(name, "$ entry points") == 0)  return "entry point table";
    if (qstrcmp(name, "$ imports") == 0)       return "import table";
    if (qstrncmp(name, "$ ", 2) == 0)          return "IDA internal";
    return nullptr;
}

// Whether a node belongs to IDA. Its nodes are conventionally named "$ ...", and
// rewriting one from the outside is how a database gets quietly broken.
bool is_reserved(const std::string &name)
{
    return name.size() >= 2 && name[0] == '$' && name[1] == ' ';
}

netnode require_node(const std::string &name, bool create)
{
    netnode n(name.c_str(), name.size(), create);
    if (!create && (nodeidx_t)n == BADNODE)
        throw std::runtime_error("no netnode named '" + name + "'");
    return n;
}

// What a named node holds, without needing to know its layout in advance.
json cmd_netnode_get(const json &params)
{
    const std::string name = require_str(params, "name");
    netnode n = require_node(name, false);

    json out = {
        { "name",     name },
        { "index",    (uint64)(nodeidx_t)n },
        { "reserved", is_reserved(name) },
    };
    if (const char *desc = well_known_node(name.c_str()))
        out["known_as"] = desc;

    // A node can carry a value, numbered slots, and a string-keyed hash at once.
    if (n.value_exists())
    {
        qstring v;
        if (n.valstr(&v) > 0)
            out["value"] = v.c_str();
        out["value_long"] = (uint64)n.long_value();
    }

    json alts = json::array();
    const size_t limit = opt_limit(params, 64);
    for (nodeidx_t i = n.altfirst(); i != BADNODE && alts.size() < limit; i = n.altnext(i))
        alts.push_back({ { "index", (uint64)i }, { "value", (uint64)n.altval(i) } });
    out["alt_count"] = (int)alts.size();
    out["alts"] = alts;

    json sups = json::array();
    for (nodeidx_t i = n.supfirst(); i != BADNODE && sups.size() < limit; i = n.supnext(i))
    {
        qstring s;
        n.supstr(&s, i);
        sups.push_back({ { "index", (uint64)i }, { "value", s.c_str() } });
    }
    out["sup_count"] = (int)sups.size();
    out["sups"] = sups;

    return out;
}

// Enumerates the nodes present, which is the only way to discover what a plugin or
// loader stored without already knowing its node name.
json cmd_netnode_list(const json &params)
{
    const size_t limit = opt_limit(params, 100);
    const std::string filter = opt_str(params, "filter");
    const bool include_reserved = params.value("include_reserved", true);

    json nodes = json::array();
    netnode n;
    for (bool ok = n.start(); ok && nodes.size() < limit; ok = n.next())
    {
        qstring name;
        if (n.get_name(&name) <= 0)
            continue;
        const std::string sname = name.c_str();
        if (!include_reserved && is_reserved(sname))
            continue;
        if (!filter.empty() && qstrstr(name.c_str(), filter.c_str()) == nullptr)
            continue;

        json entry = {
            { "name",     sname },
            { "index",    (uint64)(nodeidx_t)n },
            { "reserved", is_reserved(sname) },
        };
        if (const char *desc = well_known_node(name.c_str()))
            entry["known_as"] = desc;
        nodes.push_back(entry);
    }

    return { { "returned", (int)nodes.size() }, { "nodes", nodes } };
}

// Creates or updates a node the caller owns. Reserved names are refused: a mistake
// there damages the database in a way nothing reports and nothing undoes.
json cmd_netnode_set(const json &params)
{
    const std::string name = require_str(params, "name");
    if (is_reserved(name))
        throw std::runtime_error(
            "'" + name + "' is reserved for IDA; writing to it can corrupt the database");

    netnode n = require_node(name, true);

    if (params.contains("value"))
    {
        const std::string v = require_str(params, "value");
        if (!n.set(v.c_str(), v.size() + 1))
            throw std::runtime_error("failed to store the value");
    }
    if (params.contains("index") && params.contains("alt"))
    {
        const auto idx = (nodeidx_t)opt_size(params, "index", 0);
        const auto alt = (nodeidx_t)opt_size(params, "alt", 0);
        if (!n.altset(idx, alt))
            throw std::runtime_error("failed to store the numbered slot");
    }

    return { { "name", name }, { "index", (uint64)(nodeidx_t)n }, { "success", true } };
}

// ---- srclang ----

struct srclang_name_t
{
    srclang_t   lang;
    const char *name;
};

const srclang_name_t kLanguages[] = {
    { SRCLANG_C,      "c"      },
    { SRCLANG_CPP,    "cpp"    },
    { SRCLANG_OBJC,   "objc"   },
    { SRCLANG_SWIFT,  "swift"  },
    { SRCLANG_GO,     "go"     },
    { SRCLANG_OBJCPP, "objcpp" },
};

srclang_t srclang_from_name(const std::string &s)
{
    for (const srclang_name_t &e : kLanguages)
        if (s == e.name)
            return e.lang;
    throw std::runtime_error("unknown source language '" + s + "'");
}

// Which parser declarations are currently read with, and what else is on offer.
json cmd_parser_status(const json &)
{
    qstring current;
    get_selected_parser_name(&current);

    json langs = json::array();
    for (const srclang_name_t &e : kLanguages)
        langs.push_back(e.name);

    return {
        { "parser",    current.empty() ? json(nullptr) : json(current.c_str()) },
        { "languages", langs },
    };
}

// Switches the parser. Declaring a Swift or Go type through the C parser either
// fails or silently produces the wrong layout, so this is a prerequisite rather
// than a preference.
json cmd_select_parser(const json &params)
{
    if (params.contains("language"))
    {
        const std::string lang = require_str(params, "language");
        if (!select_parser_by_srclang(srclang_from_name(lang)))
            throw std::runtime_error("no parser available for language '" + lang + "'");
    }
    else
    {
        const std::string name = require_str(params, "parser");
        if (!select_parser_by_name(name.c_str()))
            throw std::runtime_error("no parser named '" + name + "'");
    }

    qstring current;
    get_selected_parser_name(&current);
    return { { "parser", current.c_str() }, { "success", true } };
}

// Parses declarations with the parser for a named language, rather than the C
// parser that declare_type uses.
json cmd_declare_type_for(const json &params)
{
    const std::string lang = require_str(params, "language");
    const std::string decl = require_str(params, "decl");

    const int errors = parse_decls_for_srclang(srclang_from_name(lang), nullptr,
                                               decl.c_str(), false);
    // parse_decls returns an error count; negative means the parse never ran.
    if (errors < 0)
        throw std::runtime_error("the " + lang + " parser is unavailable");

    return {
        { "language", lang },
        { "errors",   errors },
        { "success",  errors == 0 },
    };
}

// ---- undo ----

// What the next undo or redo would revert, so a caller can check before acting.
json cmd_undo_status(const json &)
{
    qstring undo_label;
    qstring redo_label;
    const bool has_undo = get_undo_action_label(&undo_label);
    const bool has_redo = get_redo_action_label(&redo_label);

    return {
        { "can_undo", has_undo },
        { "can_redo", has_redo },
        { "undo",     has_undo ? json(undo_label.c_str()) : json(nullptr) },
        { "redo",     has_redo ? json(redo_label.c_str()) : json(nullptr) },
    };
}

// Marks a point to come back to. Call it before a batch of edits, not after.
//
// The bytes handed to create_undo_point are the UNDO_ACTION_START record body, not
// a display label: IDA derives what undo_status shows from the actions recorded
// after the point, so a fresh point reports an empty label until something is
// edited. The tag is passed through for traceability, nothing more.
json cmd_undo_point(const json &params)
{
    const std::string tag = opt_str(params, "tag", "ida-hive");
    if (!create_undo_point(reinterpret_cast<const uchar *>(tag.c_str()), tag.size()))
        throw std::runtime_error("failed to create an undo point (undo may be disabled)");
    return { { "tag", tag }, { "success", true } };
}

json cmd_undo(const json &)
{
    qstring label;
    const bool had = get_undo_action_label(&label);
    if (!had)
        throw std::runtime_error("nothing to undo");
    if (!perform_undo())
        throw std::runtime_error("undo failed");
    return { { "undone", label.c_str() }, { "success", true } };
}

json cmd_redo(const json &)
{
    qstring label;
    const bool had = get_redo_action_label(&label);
    if (!had)
        throw std::runtime_error("nothing to redo");
    if (!perform_redo())
        throw std::runtime_error("redo failed");
    return { { "redone", label.c_str() }, { "success", true } };
}

const command_entry_t kCommands[] = {
    { "netnode_get",       cmd_netnode_get       },
    { "netnode_list",      cmd_netnode_list      },
    { "netnode_set",       cmd_netnode_set       },
    { "parser_status",     cmd_parser_status     },
    { "select_parser",     cmd_select_parser     },
    { "declare_type_for",  cmd_declare_type_for  },
    { "undo_status",       cmd_undo_status       },
    { "undo_point",        cmd_undo_point        },
    { "undo",              cmd_undo              },
    { "redo",              cmd_redo              },
};

}  // namespace

void register_database_commands(CommandDispatcher &dispatcher)
{
    dispatcher.register_table(kCommands);
}

}  // namespace ida_hive
