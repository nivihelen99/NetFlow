#ifndef NETFLOW_MANAGEMENT_INTERFACE_HPP
#define NETFLOW_MANAGEMENT_INTERFACE_HPP

#include <string>
#include <vector>
#include <map>
#include <functional> // For std::function
#include <optional>   // For std::optional
#include <sstream>    // For std::istringstream
#include <utility>    // For std::move

// It's good practice to forward declare if full definitions aren't needed by this header.
// However, for handler signatures, full types might be needed.
// For now, assume types like Packet, MacAddress etc. are not directly part of these basic structs.
// If they were (e.g. a handler takes a Packet), then "packet.hpp" would be needed.

namespace netflow {

enum class HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    // OPTIONS, HEAD, etc. could be added
};

struct HttpRequest {
    std::string path;
    HttpMethod method = HttpMethod::GET;
    std::map<std::string, std::string> headers;
    std::string body; // Could be std::vector<char> or a variant for different content types
};

struct HttpResponse {
    int status_code = 200; // Default to OK
    std::map<std::string, std::string> headers;
    std::string body;

    // Convenience constructor
    HttpResponse(int code = 200,
                 std::map<std::string, std::string> hdrs = {},
                 std::string bdy = "")
        : status_code(code), headers(std::move(hdrs)), body(std::move(bdy)) {}
};

class ManagementInterface {
public:
    ManagementInterface() = default;

    // --- SNMP-like OID Handling ---
    using OidGetter = std::function<std::string()>; // Getter returns string representation of value
    using OidSetter = std::function<bool(const std::string&)>; // Setter takes string representation, returns success

    struct OidHandler {
        OidGetter getter;
        std::optional<OidSetter> setter; // Setter is optional (read-only OIDs)
    };

    void register_oid_handler(const std::string& oid, OidGetter getter, std::optional<OidSetter> setter = std::nullopt) {
        oid_handlers_[oid] = {std::move(getter), std::move(setter)};
    }

    // Placeholder for actually handling an OID GET request.
    std::optional<std::string> handle_oid_get(const std::string& oid) const {
        auto it = oid_handlers_.find(oid);
        if (it != oid_handlers_.end() && it->second.getter) {
            return it->second.getter();
        }
        return std::nullopt; // OID not found or no getter
    }

    // Placeholder for actually handling an OID SET request.
    bool handle_oid_set(const std::string& oid, const std::string& value) const {
        auto it = oid_handlers_.find(oid);
        if (it != oid_handlers_.end() && it->second.setter.has_value()) {
            return it->second.setter.value()(value); // Call the setter
        }
        return false; // OID not found, not settable, or setter failed
    }

    // --- REST API Endpoint Handling ---
    using RestHandler = std::function<HttpResponse(const HttpRequest&)>;

    struct RestEndpointKey {
        std::string path;
        HttpMethod method;

        // operator< for std::map key comparison
        bool operator<(const RestEndpointKey& other) const {
            if (path != other.path) {
                return path < other.path;
            }
            return method < other.method;
        }
    };

    void register_rest_endpoint(const std::string& path, HttpMethod method, RestHandler handler) {
        rest_endpoints_[{path, method}] = std::move(handler);
    }

    // Placeholder for dispatching an incoming REST request to a registered handler.
    HttpResponse handle_rest_request(const HttpRequest& request) const {
        auto it = rest_endpoints_.find({request.path, request.method});
        if (it != rest_endpoints_.end()) {
            return it->second(request); // Call the registered handler
        }
        // Default response for unhandled paths/methods
        return {404, {{"Content-Type", "text/plain"}}, "Error 404: Not Found"};
    }

    // --- CLI Command Handling ---
    using CliHandler = std::function<std::string(const std::vector<std::string>& args)>; // Handler returns string response

    void register_command(const std::string& command_name, CliHandler handler) {
        cli_commands_[command_name] = std::move(handler);
    }

    // Placeholder for parsing and dispatching a CLI command line.
    std::string handle_cli_command(const std::string& command_line) const {
        if (command_line.empty()) {
            return "Error: Empty command.";
        }

        std::vector<std::string> parts;
        std::string current_part;
        std::istringstream iss(command_line);

        // Simple space-based tokenization. Doesn't handle quotes or complex arguments.
        while(iss >> current_part) {
            parts.push_back(current_part);
        }

        if (parts.empty()) {
            return "Error: Empty command after parsing."; // Should not happen if command_line wasn't empty
        }

        const std::string& command_name = parts[0];
        auto it = cli_commands_.find(command_name);
        if (it != cli_commands_.end()) {
            std::vector<std::string> args;
            if (parts.size() > 1) {
                args.assign(parts.begin() + 1, parts.end());
            }
            return it->second(args); // Call the handler with arguments
        }
        return "Error: Unknown command '" + command_name + "'. Type 'help' for available commands.";
    }

private:
    std::map<std::string, OidHandler> oid_handlers_;
    std::map<RestEndpointKey, RestHandler> rest_endpoints_;
    std::map<std::string, CliHandler> cli_commands_;
};

} // namespace netflow

#endif // NETFLOW_MANAGEMENT_INTERFACE_HPP
