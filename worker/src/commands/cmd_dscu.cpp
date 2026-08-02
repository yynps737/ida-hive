#include "ida_hive/pch.hpp"

#include <ida.hpp>
#include <dscu.h>

#include "ida_hive/commands.hpp"
#include "ida_hive/util.hpp"
#include "ida_hive/params.hpp"

namespace ida_hive {
namespace {

// Apple ships system libraries pre-linked into one dyld shared cache rather than as
// separate files, so an address alone says nothing about which image it belongs to.
// IDA 9.4 exposes the cache structure through dscu; these tools surface it.
//
// get_dscu_svc() returns nullptr whenever the database is not a shared cache, which
// is the normal case for every other input, so each tool reports that rather than
// failing.

dscu_svc_t &require_dscu()
{
    dscu_svc_t *svc = get_dscu_svc();
    if (svc == nullptr)
        throw std::runtime_error(
            "not a dyld shared cache database (dscu services unavailable)");
    return *svc;
}

const char *region_type_name(region_type_t t)
{
    switch (t)
    {
        case rt_image_entity: return "image_entity";
        case rt_island:       return "branch_island";
        case rt_header:       return "dyld_header";
        case rt_mapping:      return "subcache_mapping";
        case rt_got:          return "got";
        case rt_cache_data:   return "cache_data";
        case rt_unknown:      return "unknown";
        case rt_invalid:      return "invalid";
    }
    return "invalid";
}

// Cheap probe so a caller can branch on cache-ness without handling an error.
json cmd_dsc_status(const json &)
{
    dscu_svc_t *svc = get_dscu_svc();
    if (svc == nullptr)
        return { { "is_shared_cache", false } };

    qstring path;
    svc->get_input_file_path(&path);

    qstrvec_t files;
    svc->get_files_names(&files);

    return {
        { "is_shared_cache", true },
        { "path",            path.c_str() },
        { "images",          svc->get_images_count() },
        { "files",           (int)files.size() },
        { "dyld_slide",      (int64_t)svc->get_dyld_slide() },
    };
}

// The images the cache contains. `loaded` marks the ones already mapped into the
// database; the rest are known but not yet analyzable.
json cmd_dsc_images(const json &params)
{
    dscu_svc_t &svc = require_dscu();
    const size_t limit  = opt_limit(params, 200);
    const std::string filter = opt_str(params, "filter");
    const bool loaded_only = params.value("loaded_only", false);

    const int count = svc.get_images_count();
    json images = json::array();
    for (int i = 0; i < count && images.size() < limit; i++)
    {
        qstring name;
        if (!svc.get_image_name(&name, i))
            continue;
        if (!filter.empty() && qstrstr(name.c_str(), filter.c_str()) == nullptr)
            continue;

        const bool loaded = svc.is_image_loaded(i);
        if (loaded_only && !loaded)
            continue;

        images.push_back({
            { "index",  i },
            { "name",   name.c_str() },
            { "loaded", loaded },
            { "ea",     ea_hex(svc.get_image_address(i)) },
            { "size",   (uint64)svc.get_image_total_size(i) },
        });
    }

    return { { "total", count }, { "returned", (int)images.size() }, { "images", images } };
}

// Which image and region an address falls in — the question that has no answer
// without the cache metadata.
json cmd_dsc_locate(const json &params)
{
    dscu_svc_t &svc = require_dscu();
    const ea_t ea = require_ea(params);

    const address_info_t info = svc.locate_address(ea);
    if (!info.valid())
        return { { "ea", ea_hex(ea) }, { "found", false } };

    json out = {
        { "ea",          ea_hex(ea) },
        { "found",       true },
        { "file_offset", (uint64)info.file_offset },
        { "region",      {
            { "type",  region_type_name(info.region.type) },
            { "name",  info.region.name },
            { "start", ea_hex(info.region.start) },
            { "size",  (uint64)info.region.size },
        } },
    };

    if (info.region.type == rt_image_entity && info.region.image_index >= 0)
    {
        qstring name;
        if (svc.get_image_name(&name, info.region.image_index))
        {
            out["image"] = {
                { "index", info.region.image_index },
                { "name",  name.c_str() },
            };
        }
    }
    return out;
}

// An image's link dependencies, which the cache records but the mapped binary alone
// does not expose.
json cmd_dsc_dependencies(const json &params)
{
    dscu_svc_t &svc = require_dscu();
    const std::string image = require_str(params, "image");
    const int depth = (int)opt_size(params, "depth", 1);

    const int index = svc.get_image_index(image.c_str());
    if (index < 0)
        throw std::runtime_error("no such image in the cache: " + image);

    intvec_t deps;
    svc.get_image_dependencies(&deps, index, depth);

    json out = json::array();
    for (size_t i = 0; i < deps.size(); i++)
    {
        qstring name;
        if (svc.get_image_name(&name, deps[i]))
            out.push_back({ { "index", deps[i] }, { "name", name.c_str() } });
    }

    return {
        { "image",        image },
        { "index",        index },
        { "depth",        depth },
        { "dependencies", out },
    };
}

// The regions an image occupies, which are not contiguous in a shared cache.
json cmd_dsc_regions(const json &params)
{
    dscu_svc_t &svc = require_dscu();
    const std::string image = require_str(params, "image");

    const int index = svc.get_image_index(image.c_str());
    if (index < 0)
        throw std::runtime_error("no such image in the cache: " + image);

    region_info_vec_t regions;
    svc.get_image_regions(&regions, index);

    json out = json::array();
    for (size_t i = 0; i < regions.size(); i++)
        out.push_back({
            { "type",  region_type_name(regions[i].type) },
            { "name",  regions[i].name },
            { "start", ea_hex(regions[i].start) },
            { "size",  (uint64)regions[i].size },
        });

    return { { "image", image }, { "index", index }, { "regions", out } };
}

const command_entry_t kCommands[] = {
    { "dsc_status",       cmd_dsc_status       },
    { "dsc_images",       cmd_dsc_images       },
    { "dsc_locate",       cmd_dsc_locate       },
    { "dsc_dependencies", cmd_dsc_dependencies },
    { "dsc_regions",      cmd_dsc_regions      },
};

}  // namespace

void register_dscu_commands(CommandDispatcher &dispatcher)
{
    dispatcher.register_table(kCommands);
}

}  // namespace ida_hive
