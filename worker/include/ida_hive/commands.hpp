// Registration hooks for the command modules.
//
// Each module owns one translation unit under src/commands and exposes exactly the
// function below, so main() decides the registration order in one readable place.
// Modules keep their handlers in an anonymous namespace and register them from a
// table; nothing else in a module is visible outside it.

#pragma once

#include "ida_hive/protocol.hpp"

namespace ida_hive {

void register_core_commands(CommandDispatcher &dispatcher);
void register_analysis_commands(CommandDispatcher &dispatcher);
void register_memory_commands(CommandDispatcher &dispatcher);
void register_modify_commands(CommandDispatcher &dispatcher);
void register_search_commands(CommandDispatcher &dispatcher);
void register_graph_commands(CommandDispatcher &dispatcher);
void register_type_commands(CommandDispatcher &dispatcher);
void register_stack_commands(CommandDispatcher &dispatcher);
void register_composite_commands(CommandDispatcher &dispatcher);
void register_flow_commands(CommandDispatcher &dispatcher);
void register_microcode_commands(CommandDispatcher &dispatcher);
void register_dscu_commands(CommandDispatcher &dispatcher);
void register_string_commands(CommandDispatcher &dispatcher);
void register_indexer_commands(CommandDispatcher &dispatcher);
void register_signature_commands(CommandDispatcher &dispatcher);
void register_offset_commands(CommandDispatcher &dispatcher);

}  // namespace ida_hive
