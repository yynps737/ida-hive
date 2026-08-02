// The IDA SDK's pro.h macro-redefines fgetc/fputc, which breaks nlohmann/json's
// use of std::fgetc. Parsing json first makes the later redefinition harmless.

#pragma once

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
#include <chrono>
#include <nlohmann/json.hpp>

// No IDA header belongs above this line. Includers pull in ida.hpp, and with it
// pro.h, only after this point.
