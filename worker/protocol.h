// protocol.h - JSON-RPC protocol between Rust coordinator and C++ worker
//
// Wire format: JSON Lines over stdin/stdout (one JSON object per line)
//
// Request:  {"id": 1, "method": "decompile", "params": {"ea": "0x1400010A0"}}
// Response: {"id": 1, "result": {...}}
// Error:    {"id": 1, "error": {"code": -1, "message": "..."}}
// Event:    {"event": "ready", "data": {...}}  (no id, worker-initiated)
//
// IMPORTANT: This file must be included AFTER pch.h and IDA headers.
//            parse_ea / ea_hex helpers are in util.h.

#pragma once

#include <nlohmann/json.hpp>

using json = nlohmann::json;

// Command handler signature: takes params, returns result JSON
using CommandHandler = std::function<json(const json& params)>;

class CommandDispatcher
{
public:
    void register_command(const std::string& method, CommandHandler handler)
    {
        handlers_[method] = std::move(handler);
    }

    // Main loop: read stdin, dispatch, write stdout
    void run()
    {
        std::string line;
        while (std::getline(std::cin, line))
        {
            if (line.empty())
                continue;

            json response;
            try
            {
                auto request = json::parse(line);
                auto id = request.value("id", json());
                auto method = request.value("method", std::string{});
                auto params = request.value("params", json::object());

                auto it = handlers_.find(method);
                if (it == handlers_.end())
                {
                    response = {
                        {"id", id},
                        {"error", {{"code", -32601}, {"message", "Unknown method: " + method}}}
                    };
                }
                else
                {
                    try
                    {
                        json result = it->second(params);
                        response = {{"id", id}, {"result", result}};
                    }
                    catch (const std::exception& e)
                    {
                        response = {
                            {"id", id},
                            {"error", {{"code", -1}, {"message", e.what()}}}
                        };
                    }
                }
            }
            catch (const json::parse_error&)
            {
                response = {
                    {"id", nullptr},
                    {"error", {{"code", -32700}, {"message", "Parse error"}}}
                };
            }

            // Write response as single line + flush
            std::cout << response.dump() << "\n" << std::flush;
        }
    }

private:
    std::unordered_map<std::string, CommandHandler> handlers_;
};

// Helper: send an event (no id) to coordinator
inline void send_event(const std::string& event_name, const json& data = {})
{
    json event = {{"event", event_name}, {"data", data}};
    std::cout << event.dump() << "\n" << std::flush;
}
