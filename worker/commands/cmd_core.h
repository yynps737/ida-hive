// cmd_core.h - Core query commands: list_funcs, list_segments, lookup_func, get_info
#pragma once

#include "../protocol.h"

void register_core_commands(CommandDispatcher& dispatcher);
