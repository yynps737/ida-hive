// Wire format between the Rust coordinator and this worker: JSON Lines over
// stdin/stdout, one object per line. Envelopes are JSON-RPC-shaped but carry no
// `jsonrpc` field; only the reserved error codes are borrowed.
//
// Request:  {"id": 1, "method": "decompile", "params": {"ea": "0x1400010A0"}}
// Response: {"id": 1, "result": {...}}
// Error:    {"id": 1, "error": {"code": -1, "message": "..."}}
// Event:    {"event": "ready", "data": {...}}  (no id, worker-initiated)
//
// Include after pch.h and the IDA headers. parse_ea / ea_hex live in util.h.

#pragma once

#include <nlohmann/json.hpp>

using json = nlohmann::json;


namespace ida_hive {
using CommandHandler = std::function<json(const json& params)>;

// One row of a command module's registration table. Modules declare their commands
// as a static array of these so the mapping stays readable in one place.
struct command_entry_t
{
    const char*    name;
    json         (*handler)(const json& params);
};

class CommandDispatcher
{
public:
    void register_command(const std::string& method, CommandHandler handler)
    {
        handlers_[method] = std::move(handler);
    }

    template <size_t N>
    void register_table(const command_entry_t (&table)[N])
    {
        for (const command_entry_t& e : table)
            handlers_[e.name] = e.handler;
    }

private:
    // Serialization can fail after a handler has already succeeded: strings read out
    // of a binary are arbitrary bytes, and dump() rejects invalid UTF-8. Replacing
    // the offending bytes keeps the reply on the wire; failing that, the id still
    // gets an error so the caller is never left waiting.
    static void emit(const json& response)
    {
        std::string text;
        try
        {
            text = response.dump();
        }
        catch (const std::exception&)
        {
            try
            {
                text = response.dump(-1, ' ', false, json::error_handler_t::replace);
            }
            catch (const std::exception& e)
            {
                json fallback = {
                    {"id", response.contains("id") ? response["id"] : json()},
                    {"error", {{"code", -32603}, {"message", std::string("Response encoding failed: ") + e.what()}}}
                };
                text = fallback.dump(-1, ' ', false, json::error_handler_t::replace);
            }
        }
        std::cout << text << "\n" << std::flush;
    }

public:

    // Single-threaded: a slow handler blocks every later request on this worker.
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
            // A line that parses but is not an object still reaches value()/at(),
            // which throw type_error rather than parse_error. Anything else that
            // escapes a handler lands here too; letting it out would terminate the
            // process and take every other pending request with it.
            catch (const std::exception& e)
            {
                response = {
                    {"id", nullptr},
                    {"error", {{"code", -32600}, {"message", std::string("Invalid request: ") + e.what()}}}
                };
            }

            emit(response);
        }
    }

private:
    std::unordered_map<std::string, CommandHandler> handlers_;
};

// Unsolicited message to the coordinator, outside the request/response flow.
inline void send_event(const std::string& event_name, const json& data = {})
{
    json event = {{"event", event_name}, {"data", data}};
    std::string text;
    try
    {
        text = event.dump();
    }
    catch (const std::exception&)
    {
        // Same hazard as a reply: event payloads carry bytes read from the input.
        text = event.dump(-1, ' ', false, json::error_handler_t::replace);
    }
    std::cout << text << "\n" << std::flush;
}

}  // namespace ida_hive
