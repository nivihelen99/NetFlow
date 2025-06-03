#ifndef NETFLOW_MANAGEMENT_INTERFACE_HPP
#define NETFLOW_MANAGEMENT_INTERFACE_HPP

#include <string>
#include <vector>
#include <map>
#include <functional> // For std::function
#include <optional>   // For std::optional
#include <sstream>    // For std::istringstream
#include <utility>    // For std::move
#include <cstddef>    // For std::size_t

namespace netflow {

enum class HttpMethod {
    GET, POST, PUT, DELETE, PATCH
};

struct HttpRequest {
    std::string path;
    HttpMethod method = HttpMethod::GET;
    std::map<std::string, std::string> headers;
    std::string body;
};

struct HttpResponse {
    int status_code = 200;
    std::map<std::string, std::string> headers;
    std::string body;

    HttpResponse(int code = 200,
                 std::map<std::string, std::string> hdrs = {},
                 std::string bdy = "")
        : status_code(code), headers(std::move(hdrs)), body(std::move(bdy)) {}
};

class ManagementInterface {
public:
    ManagementInterface() = default;

    using OidGetter = std::function<std::string()>;
    using OidSetter = std::function<bool(const std::string&)>;

    struct OidHandler {
        OidGetter getter;
        std::optional<OidSetter> setter;
    };

    void register_oid_handler(const std::string& oid, OidGetter getter, std::optional<OidSetter> setter = std::nullopt) {
        oid_handlers_[oid] = {std::move(getter), std::move(setter)};
    }

    std::optional<std::string> handle_oid_get(const std::string& oid) const {
        auto it = oid_handlers_.find(oid);
        if (it != oid_handlers_.end() && it->second.getter) {
            return it->second.getter();
        }
        return std::nullopt;
    }

    bool handle_oid_set(const std::string& oid, const std::string& value) const {
        auto it = oid_handlers_.find(oid);
        if (it != oid_handlers_.end() && it->second.setter.has_value()) {
            return it->second.setter.value()(value);
        }
        return false;
    }

    using RestHandler = std::function<HttpResponse(const HttpRequest&)>;

    struct RestEndpointKey {
        std::string path;
        HttpMethod method;

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

    HttpResponse handle_rest_request(const HttpRequest& request) const {
        auto it = rest_endpoints_.find({request.path, request.method});
        if (it != rest_endpoints_.end()) {
            return it->second(request);
        }
        return {404, {{"Content-Type", "text/plain"}}, "Error 404: Not Found"};
    }

    using CliHandler = std::function<std::string(const std::vector<std::string>& args)>;

    void register_command(const std::vector<std::string>& command_parts, CliHandler handler) {
        if (command_parts.empty()) return;
        cli_commands_[command_parts] = std::move(handler);
    }

    std::string handle_cli_command(const std::string& command_line) const {
        if (command_line.empty()) {
            return "Error: Empty command.";
        }

        std::vector<std::string> input_parts;
        std::string current_part;
        std::istringstream iss(command_line);

        while(iss >> current_part) {
            input_parts.push_back(current_part);
        }

        if (input_parts.empty()) {
            return "Error: Empty command after parsing.";
        }

        std::vector<std::string> best_match_command_key;
        const CliHandler* best_handler = nullptr;

        for (auto const& [registered_command_key, handler_func] : cli_commands_) {
            if (input_parts.size() >= registered_command_key.size()) {
                bool prefix_match = true;
                for (std::size_t i = 0; i < registered_command_key.size(); ++i) { // Used std::size_t
                    if (input_parts[i] != registered_command_key[i]) {
                        prefix_match = false;
                        break;
                    }
                }
                if (prefix_match) {
                    if (best_handler == nullptr || registered_command_key.size() > best_match_command_key.size()) {
                        best_match_command_key = registered_command_key;
                        best_handler = &handler_func;
                    }
                }
            }
        }

        if (best_handler) {
            std::vector<std::string> args(input_parts.begin() + best_match_command_key.size(), input_parts.end());
            return (*best_handler)(args);
        }
        
        return "Error: Unknown command or prefix: " + command_line + ". Type 'help' for available commands.";
    }

private:
    std::map<std::string, OidHandler> oid_handlers_;
    std::map<RestEndpointKey, RestHandler> rest_endpoints_;
    std::map<std::vector<std::string>, CliHandler> cli_commands_;
};

} // namespace netflow

#endif // NETFLOW_MANAGEMENT_INTERFACE_HPP
