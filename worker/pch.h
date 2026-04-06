// pch.h - Precompiled header / include-order fix
//
// IDA SDK's pro.h redefines fgetc/fputc/etc. via macros, which breaks
// nlohmann/json's internal use of std::fgetc. Fix: include nlohmann/json
// FIRST, before any IDA headers.

#pragma once

// ---- Standard library + nlohmann/json FIRST ----
#include <cstdint>
#include <cstdio>
#include <string>
#include <iostream>
#include <vector>
#include <functional>
#include <unordered_map>
#include <stdexcept>
#include <sstream>
#include <regex>
#include <set>
#include <queue>
#include <nlohmann/json.hpp>

// ---- IDA SDK headers AFTER ----
// (pro.h will be pulled in by ida.hpp, redefining stdio macros,
//  but nlohmann/json is already fully parsed at this point)
