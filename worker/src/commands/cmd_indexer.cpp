#include "ida_hive/pch.hpp"

#include <ida.hpp>
#include <indexer.hpp>

#include "ida_hive/commands.hpp"
#include "ida_hive/util.hpp"
#include "ida_hive/params.hpp"

namespace ida_hive {
namespace {

// The index behind IDA 9.4's "Jump Anywhere": one query spanning functions, names,
// types, segments and comments, with optional fuzzy matching. Reaching it directly
// replaces a fan-out of per-kind list calls with a single ranked lookup.

struct subindex_name_t
{
    builtin_idxes_t id;
    const char     *name;
};

const subindex_name_t kSubindexes[] = {
    { SUBIDX_FUNCTIONS,                    "functions"          },
    { SUBIDX_LTYPES,                       "types"              },
    { SUBIDX_NAMES,                        "names"              },
    { SUBIDX_SEGMENTS,                     "segments"           },
    { SUBIDX_FUNCTION_COMMENTS,            "comments"           },
    { SUBIDX_REPEATABLE_FUNCTION_COMMENTS, "repeatable_comments"},
};

const char *subindex_to_name(subindex_typeid_t id)
{
    for (const subindex_name_t &e : kSubindexes)
        if ((subindex_typeid_t)e.id == id)
            return e.name;
    return "unknown";
}

builtin_idxes_t subindex_from_name(const std::string &s)
{
    for (const subindex_name_t &e : kSubindexes)
        if (s == e.name)
            return e.id;
    throw std::runtime_error("unknown index '" + s + "'");
}

// Owns the result set, which the API hands over to the caller.
class results_holder_t
{
public:
    explicit results_holder_t(search_result_data_t *p) : ptr_(p) {}
    ~results_holder_t() { delete ptr_; }
    results_holder_t(const results_holder_t &) = delete;
    results_holder_t &operator=(const results_holder_t &) = delete;
    search_result_data_t *get() const { return ptr_; }

private:
    search_result_data_t *ptr_;
};

void require_indexer()
{
    if (!indexer_is_enabled())
        throw std::runtime_error("the indexer is disabled for this database");
}

match_config_t make_config(const json &params)
{
    match_config_t cfg;
    cfg.mode = opt_str(params, "mode") == "fuzzy" ? match_mode_t::FUZZY
                                                  : match_mode_t::STR_MATCH;
    cfg.max_results  = (int)opt_limit(params, 100, 2000);
    cfg.score_cutoff = (int)opt_size(params, "score_cutoff", 0);
    return cfg;
}

json render(search_result_data_t &res)
{
    json out = json::array();
    for (size_t i = 0; i < res.size(); i++)
    {
        const ea_t ea = res.get_ea(i);
        out.push_back({
            { "name",  res.get_name_str(i).c_str() },
            { "index", subindex_to_name(res.get_subindex(i)) },
            { "score", res.get_score(i) },
            // Types and comments carry no address of their own.
            { "ea",    ea == BADADDR ? json(nullptr) : json(ea_hex(ea)) },
        });
    }
    return out;
}

// One query across every index.
json cmd_index_search(const json &params)
{
    require_indexer();
    const std::string needle = require_str(params, "query");
    const match_config_t cfg = make_config(params);

    results_holder_t res(indexer_match_all(qstring(needle.c_str()), cfg));
    if (res.get() == nullptr)
        return { { "query", needle }, { "count", 0 }, { "results", json::array() } };

    json items = render(*res.get());
    return {
        { "query",   needle },
        { "mode",    cfg.mode == match_mode_t::FUZZY ? "fuzzy" : "substring" },
        { "count",   (int)items.size() },
        { "results", items },
    };
}

// The same query restricted to one index, for when the kind is already known.
json cmd_index_search_kind(const json &params)
{
    require_indexer();
    const std::string needle = require_str(params, "query");
    const std::string kind   = require_str(params, "index");
    const builtin_idxes_t sub = subindex_from_name(kind);
    const match_config_t cfg = make_config(params);

    results_holder_t res(indexer_match((subindex_typeid_t)sub, qstring(needle.c_str()), cfg));
    if (res.get() == nullptr)
        return { { "query", needle }, { "index", kind }, { "count", 0 },
                 { "results", json::array() } };

    json items = render(*res.get());
    return {
        { "query",   needle },
        { "index",   kind },
        { "mode",    cfg.mode == match_mode_t::FUZZY ? "fuzzy" : "substring" },
        { "count",   (int)items.size() },
        { "results", items },
    };
}

// Availability plus the index names, so a caller can pick one without guessing.
json cmd_index_status(const json &)
{
    json names = json::array();
    for (const subindex_name_t &e : kSubindexes)
        names.push_back(e.name);
    return {
        { "enabled", indexer_is_enabled() },
        { "indexes", names },
        { "modes",   json::array({ "substring", "fuzzy" }) },
    };
}

const command_entry_t kCommands[] = {
    { "index_search",      cmd_index_search      },
    { "index_search_kind", cmd_index_search_kind },
    { "index_status",      cmd_index_status      },
};

}  // namespace

void register_indexer_commands(CommandDispatcher &dispatcher)
{
    dispatcher.register_table(kCommands);
}

}  // namespace ida_hive
