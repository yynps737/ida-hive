// cmd_analysis.h - Analysis commands: decompile, disasm, xrefs_to, callees
#pragma once

#include "../protocol.h"

void register_analysis_commands(CommandDispatcher& dispatcher);
