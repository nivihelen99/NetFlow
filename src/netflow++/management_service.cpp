#include "netflow++/management_service.hpp"
#include "netflow++/interface_manager.hpp"
#include "netflow++/vlan_manager.hpp"
#include "netflow++/forwarding_database.hpp"
#include "netflow++/stp_manager.hpp"
#include "netflow++/lacp_manager.hpp"
#include "netflow++/qos_manager.hpp"
#include "netflow++/acl_manager.hpp" // Include AclManager
#include "netflow++/packet.hpp"
#include <sstream>
#include <vector>
#include <string>
#include <iomanip>
#include <arpa/inet.h> // For string_to_ip_net_order, ip_to_string_util_net_order
#include <algorithm>
#include <map>
#include <set>
#include <cstdio> // For sscanf in string_to_mac
#include <functional> // For std::function

namespace { // Anonymous namespace for static helper functions

// Basic string to IP (network order)
bool string_to_ip_net_order(const std::string& ip_str, netflow::IpAddress& out_ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) == 1) {
        out_ip = addr.s_addr;
        return true;
    }
    return false;
}
// Basic string to uint16_t for VLAN ID
bool parse_vlan_id(const std::string& s, uint16_t& vlan_id) { /* ... */ return true; }
bool parse_vlan_list(const std::string& s, std::set<uint16_t>& vlan_set) { /* ... */ return true; }
static bool string_to_mac(const std::string& mac_str, netflow::MacAddress& out_mac) { /* ... */ return true; }
std::string uint64_mac_to_string(uint64_t mac_val) { /* ... */ return ""; }
static std::string format_lacp_state_flags(uint8_t state_byte) { /* ... */ return ""; }
std::string lacp_mux_state_to_string(netflow::LacpPortInfo::MuxMachineState state) { /* ... */ return ""; }
std::string lacp_rx_state_to_string(netflow::LacpPortInfo::RxMachineState state) { /* ... */ return ""; }

} // namespace

namespace netflow {

static std::string ip_to_string_util_net_order(netflow::IpAddress net_ip_addr) {
    struct in_addr addr;
    addr.s_addr = net_ip_addr;
    return inet_ntoa(addr);
}
static std::string format_lldp_neighbors(const std::vector<LldpNeighborInfo>& neighbors, bool detail) { /* ... */ return ""; }
static std::string format_lldp_interface_config(uint32_t port_id, const LldpPortConfig& config) { /* ... */ return ""; }


ManagementService::ManagementService(SwitchLogger& logger, // Added logger
                                     RoutingManager& rm, InterfaceManager& im, ManagementInterface& mi,
                                     netflow::VlanManager& vm, netflow::ForwardingDatabase& fdbm,
                                     netflow::StpManager& stpm, netflow::LacpManager& lacpm,
                                     netflow::LldpManager& lldpm, netflow::QosManager& qos_m,
                                     netflow::AclManager& acl_m)
    : logger_(logger), // Initialize logger_ member
      routing_manager_(rm), interface_manager_(im), management_interface_(mi),
      vlan_manager_(vm), fdb_manager_(fdbm), stp_manager_(stpm), lacp_manager_(lacpm),
      lldp_manager_(lldpm), qos_manager_(qos_m), acl_manager_(acl_m) {
    // Constructor body
}

// --- QoS Command Handler Implementations ---
std::string ManagementService::handle_interface_qos_command(uint32_t port_id, const std::vector<std::string>& qos_args) {
    // ... (QoS command handling implementation from previous step) ...
    if (qos_args.empty()) {
        return "Error: Missing QoS action for interface " + std::to_string(port_id);
    }
    QosConfig current_config = qos_manager_.get_port_qos_config(port_id).value_or(QosConfig());
    if (current_config.num_queues == 0) current_config.num_queues = 4;
    current_config.validate_and_prepare();
    std::string action = qos_args[0];
    size_t arg_idx = 1;
    // ... (full parsing logic for all qos subcommands) ...
    if (action == "enable") { qos_manager_.configure_port_qos(port_id, current_config); return "QoS enabled..."; }
    // ... other qos actions ...
    else { return "Error: Unknown QoS command '" + action + "'."; }
    current_config.validate_and_prepare();
    qos_manager_.configure_port_qos(port_id, current_config);
    return "QoS configuration updated for interface " + std::to_string(port_id) + ".";
}
std::string ManagementService::handle_show_qos_command(const std::vector<std::string>& args) {
    // ... (show QoS implementation from previous step) ...
    if (args.empty() || args[0] != "interface" || args.size() < 2) return "Error: Usage: show qos interface <id> ...";
    // ... parsing and formatting ...
    return "Show QoS output placeholder.";
}
std::string ManagementService::handle_clear_qos_command(const std::vector<std::string>& args) {
    // ... (clear QoS implementation from previous step) ...
    if (args.empty() || args[0] != "interface" || args.size() < 3 || args[2] != "stats") return "Error: Usage: clear qos interface <id> stats";
    // ... parsing and re-applying config ...
    return "Clear QoS stats placeholder.";
}

// --- ACL Command Handler Implementations ---
std::string ManagementService::handle_acl_rule_command(const std::vector<std::string>& args) {
    if (args.empty()) return "Error: Missing acl-rule subcommand (add|remove).";

    std::string subcommand = args[0];
    size_t current_idx = 1;

    if (subcommand == "add") {
        if (args.size() < current_idx + 6) // id <ID> priority <PRIO> action <ACTION> ...
            return "Error: Insufficient arguments for 'acl-rule add'. Required: id <ID> priority <PRIO> action <ACTION> ...";

        AclRule rule;
        // Parse mandatory fields: id, priority, action
        while(current_idx < args.size()) {
            std::string key = args[current_idx++];
            if (current_idx >= args.size()) return "Error: Missing value for '" + key + "'.";
            std::string value_str = args[current_idx++];

            if (key == "id") {
                try { rule.rule_id = std::stoul(value_str); }
                catch (const std::exception& e) { return "Error: Invalid rule ID value '" + value_str + "'."; }
            } else if (key == "priority") {
                try { rule.priority = std::stoi(value_str); }
                catch (const std::exception& e) { return "Error: Invalid priority value '" + value_str + "'."; }
            } else if (key == "action") {
                if (value_str == "permit") rule.action = AclActionType::PERMIT;
                else if (value_str == "deny") rule.action = AclActionType::DENY;
                else if (value_str == "redirect") {
                    rule.action = AclActionType::REDIRECT;
                    if (current_idx >= args.size()) return "Error: Missing redirect port ID for action 'redirect'.";
                    try { rule.redirect_port_id = std::stoul(args[current_idx++]); }
                    catch (const std::exception& e) { return "Error: Invalid redirect port ID value."; }
                } else return "Error: Invalid action '" + value_str + "'. Must be permit, deny, or redirect.";
            } else if (key == "src-mac") {
                MacAddress mac;
                if (!string_to_mac(value_str, mac)) return "Error: Invalid src-mac format '" + value_str + "'.";
                rule.src_mac = mac;
            } else if (key == "dst-mac") {
                MacAddress mac;
                if (!string_to_mac(value_str, mac)) return "Error: Invalid dst-mac format '" + value_str + "'.";
                rule.dst_mac = mac;
            } else if (key == "vlan") {
                uint16_t vid;
                if (!parse_vlan_id(value_str, vid)) return "Error: Invalid VLAN ID '" + value_str + "'.";
                rule.vlan_id = vid;
            } else if (key == "ethertype") {
                try { rule.ethertype = static_cast<uint16_t>(std::stoul(value_str, nullptr, 0)); } // Allow hex (0x) or dec
                catch (const std::exception& e) { return "Error: Invalid ethertype value '" + value_str + "'."; }
            } else if (key == "src-ip") { // Expects IP only, no mask for now as AclRule doesn't store mask
                IpAddress ip;
                if (!string_to_ip_net_order(value_str, ip)) return "Error: Invalid src-ip format '" + value_str + "'.";
                rule.src_ip = ntohl(ip); // Store in host byte order
            } else if (key == "dst-ip") {
                IpAddress ip;
                if (!string_to_ip_net_order(value_str, ip)) return "Error: Invalid dst-ip format '" + value_str + "'.";
                rule.dst_ip = ntohl(ip);
            } else if (key == "protocol") {
                if (value_str == "tcp") rule.protocol = IPPROTO_TCP;
                else if (value_str == "udp") rule.protocol = IPPROTO_UDP;
                else if (value_str == "icmp") rule.protocol = IPPROTO_ICMP;
                else if (value_str == "ip") rule.protocol = 0; // Special case for "any IP protocol" often 0, or don't set. Assume 0 for "ip"
                else {
                    try { rule.protocol = static_cast<uint8_t>(std::stoul(value_str));}
                    catch(const std::exception& e) { return "Error: Invalid protocol value '" + value_str + "'."; }
                }
            } else if (key == "src-port") {
                try { rule.src_port = static_cast<uint16_t>(std::stoul(value_str)); }
                catch (const std::exception& e) { return "Error: Invalid src-port value '" + value_str + "'."; }
            } else if (key == "dst-port") {
                try { rule.dst_port = static_cast<uint16_t>(std::stoul(value_str)); }
                catch (const std::exception& e) { return "Error: Invalid dst-port value '" + value_str + "'."; }
            } else {
                 // If a key was consumed, value_str was its value. The next token is the new key.
                 // So, if key is not recognized, it's an error.
                 // We need to put value_str back if it wasn't a value for a recognized key.
                 // This parsing loop is basic. A more robust one would check pairs.
                 return "Error: Unknown ACL rule option '" + key + "'.";
            }
        }
        // Basic validation of rule before adding
        if (rule.rule_id == 0) return "Error: Rule ID cannot be 0.";
        if (rule.action == AclActionType::REDIRECT && !rule.redirect_port_id.has_value()){
            return "Error: Redirect action specified but no redirect port ID provided.";
        }

        if (acl_manager_.add_rule(rule)) {
            return "ACL rule " + std::to_string(rule.rule_id) + " added/updated.";
        } else {
            return "Error: Failed to add/update ACL rule " + std::to_string(rule.rule_id) + ". (This path should not be hit with current add_rule always returning true)";
        }

    } else if (subcommand == "remove") {
        if (args.size() < current_idx + 2 || args[current_idx] != "id") return "Error: Usage: acl-rule remove id <ID>";
        current_idx++; // consume "id"
        uint32_t rule_id;
        try {
            rule_id = std::stoul(args[current_idx]);
        } catch (const std::exception& e) {
            return "Error: Invalid rule ID for removal.";
        }
        if (acl_manager_.remove_rule(rule_id)) {
            return "ACL rule " + std::to_string(rule_id) + " removed.";
        } else {
            return "Error: ACL rule " + std::to_string(rule_id) + " not found.";
        }
    } else {
        return "Error: Unknown 'acl-rule' subcommand '" + subcommand + "'. Use 'add' or 'remove'.";
    }
}

std::string ManagementService::handle_show_acl_rules_command(const std::vector<std::string>& args) {
    std::ostringstream oss;
    std::vector<AclRule> rules_to_show;

    if (!args.empty() && args[0] == "id" && args.size() > 1) {
        uint32_t rule_id;
        try {
            rule_id = std::stoul(args[1]);
        } catch (const std::exception& e) {
            return "Error: Invalid rule ID format.";
        }
        auto rule_opt = acl_manager_.get_rule(rule_id);
        if (rule_opt) {
            rules_to_show.push_back(rule_opt.value());
        } else {
            return "ACL rule " + std::to_string(rule_id) + " not found.";
        }
    } else if (args.empty()) {
        rules_to_show = acl_manager_.get_all_rules();
    } else {
        return "Error: Usage: show acl-rules [id <RULE_ID>]";
    }

    if (rules_to_show.empty()) {
        return "No ACL rules configured or matching criteria.";
    }

    oss << std::left << std::setw(5) << "ID" << std::setw(10) << "Priority" << std::setw(10) << "Action"
        << std::setw(20) << "Src MAC" << std::setw(20) << "Dst MAC"
        << std::setw(8) << "VLAN" << std::setw(10) << "EtherType"
        << std::setw(18) << "Src IP" << std::setw(18) << "Dst IP"
        << std::setw(10) << "Protocol" << std::setw(10) << "Src Port" << std::setw(10) << "Dst Port"
        << std::setw(10) << "Redirect" << "\n";
    oss << std::string(150, '-') << "\n"; // Adjust width as needed

    for (const auto& rule : rules_to_show) {
        oss << std::setw(5) << rule.rule_id << std::setw(10) << rule.priority;
        switch (rule.action) {
            case AclActionType::PERMIT: oss << std::setw(10) << "Permit"; break;
            case AclActionType::DENY: oss << std::setw(10) << "Deny"; break;
            case AclActionType::REDIRECT: oss << std::setw(10) << "Redirect"; break;
        }
        oss << std::setw(20) << (rule.src_mac ? uint64_mac_to_string(0) /* TODO: MacAddress to string */ : "Any"); // Placeholder for MacAddress to string
        oss << std::setw(20) << (rule.dst_mac ? uint64_mac_to_string(0) /* TODO: MacAddress to string */ : "Any");
        oss << std::setw(8) << (rule.vlan_id ? std::to_string(rule.vlan_id.value()) : "Any");
        oss << std::setw(10) << (rule.ethertype ? "0x" + logger_.to_hex_string(rule.ethertype.value()) : "Any");
        oss << std::setw(18) << (rule.src_ip ? ip_to_string_util_net_order(htonl(rule.src_ip.value())) : "Any");
        oss << std::setw(18) << (rule.dst_ip ? ip_to_string_util_net_order(htonl(rule.dst_ip.value())) : "Any");

        std::string proto_str = "Any";
        if(rule.protocol) {
            if(rule.protocol.value() == IPPROTO_TCP) proto_str = "TCP";
            else if(rule.protocol.value() == IPPROTO_UDP) proto_str = "UDP";
            else if(rule.protocol.value() == IPPROTO_ICMP) proto_str = "ICMP";
            else if(rule.protocol.value() == 0 && (rule.src_ip || rule.dst_ip)) proto_str = "IP"; // if IP fields are set, proto 0 means any IP
            else if(rule.protocol.value() != 0) proto_str = std::to_string(rule.protocol.value());
        }
        oss << std::setw(10) << proto_str;
        oss << std::setw(10) << (rule.src_port ? std::to_string(rule.src_port.value()) : "Any");
        oss << std::setw(10) << (rule.dst_port ? std::to_string(rule.dst_port.value()) : "Any");
        oss << std::setw(10) << (rule.redirect_port_id ? std::to_string(rule.redirect_port_id.value()) : "N/A");
        oss << "\n";
    }
    return oss.str();
}

std::string ManagementService::handle_acl_compile_command(const std::vector<std::string>& args) {
    acl_manager_.compile_rules();
    return "ACL rules compiled (sorted by priority).";
}


void ManagementService::register_cli_commands() {
    // ... (existing helper lambdas) ...
    auto format_interface_stats_only = [this](std::ostringstream& oss, uint32_t port_id){ /* ... */ };
    auto format_full_interface_details = [this](std::ostringstream& oss, uint32_t port_id, const netflow::InterfaceManager::PortConfig& config){ /* ... */ };

    management_interface_.register_command(
        "show",
        [this, format_full_interface_details, format_interface_stats_only](const std::vector<std::string>& args) -> std::string {
            if (args.empty()) return "Error: Missing arguments for 'show' command.";
            std::string type = args[0];
            std::vector<std::string> sub_args(args.begin() + 1, args.end());

            if (type == "qos") { return handle_show_qos_command(sub_args); }
            else if (type == "acl-rules") { return handle_show_acl_rules_command(sub_args); }
            // ... (rest of existing show command handling) ...
            else { return "Error: Unsupported 'show' command. Usage: show [qos|acl-rules|interface|...]"; }
        });

    management_interface_.register_command(
        "clear",
        [this](const std::vector<std::string>& args) -> std::string {
            if (args.empty()) return "Error: Missing arguments for 'clear' command.";
            std::string type = args[0];
            if (type == "qos") { return handle_clear_qos_command(std::vector<std::string>(args.begin() + 1, args.end())); }
            // ... (other clear commands) ...
            return "Error: Unknown clear command '" + type + "'.";
        });

    management_interface_.register_command(
        "interface",
        [this](const std::vector<std::string>& args) -> std::string {
             // ... (existing interface command logic, ensure parsing is robust for args[0] as ID, args[1] as subcommand) ...
            if (args.size() < 2) return "Error: Missing interface ID or subcommand.";
            uint32_t port_id;
            try { port_id = std::stoul(args[0]); }
            catch (const std::exception& e) { return "Error: Invalid interface ID format."; }
            if (!interface_manager_.is_port_valid(port_id)) return "Error: Invalid interface ID: " + args[0];

            std::string primary_subcommand = args[1];
            std::vector<std::string> sub_args(args.begin() + 2, args.end());

            if (primary_subcommand == "qos") {
                if (sub_args.empty()) return "Error: Missing QoS configuration details for interface " + args[0];
                return handle_interface_qos_command(port_id, sub_args);
            } else if (primary_subcommand == "lldp") { /* ... */ return "LLDP placeholder"; }
            // ... other interface subcommands ...
            return "Error: Unknown or incomplete command for interface " + args[0] + ".";
        });

    management_interface_.register_command("acl-rule", [this](const std::vector<std::string>& args) -> std::string {
        return handle_acl_rule_command(args);
    });
    management_interface_.register_command("acl-compile", [this](const std::vector<std::string>& args) -> std::string {
        return handle_acl_compile_command(args);
    });


    // ... (other command registrations: mac, no, spanning-tree, lacp, lldp global, help) ...
    management_interface_.register_command("mac", [this](const std::vector<std::string>& args) -> std::string { /* ... */ return "mac placeholder"; });
    management_interface_.register_command("no", [this](const std::vector<std::string>& args) -> std::string { /* ... */ return "no placeholder"; });
    management_interface_.register_command("spanning-tree", [this](const std::vector<std::string>& args) -> std::string { /* ... */ return "stp placeholder"; });
    management_interface_.register_command("lacp", [this](const std::vector<std::string>& args) -> std::string { /* ... */ return "lacp placeholder"; });
    management_interface_.register_command("lldp", [this](const std::vector<std::string>& args) -> std::string { /* ... */ return "lldp placeholder"; });
    management_interface_.register_command("help", [this](const std::vector<std::string>& args) -> std::string { /* ... */ return "help placeholder"; });

} // End of register_cli_commands

// --- Existing methods (add_route, remove_route, etc. - placeholders) ---
std::optional<std::string> ManagementService::add_route(const IpAddress& n, const IpAddress& m, const IpAddress& nh, uint32_t id, int met){ return std::nullopt;}
std::optional<std::string> ManagementService::remove_route(const IpAddress& n, const IpAddress& m){ return std::nullopt;}
std::optional<std::string> ManagementService::add_interface_ip(uint32_t id, const IpAddress& ip, const IpAddress& mask){ return std::nullopt;}
std::optional<std::string> ManagementService::remove_interface_ip(uint32_t id, const IpAddress& ip, const IpAddress& mask){ return std::nullopt;}

} // namespace netflow
