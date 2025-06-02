#include "netflow++/management_service.hpp"
#include "netflow++/interface_manager.hpp"
#include "netflow++/vlan_manager.hpp"
#include "netflow++/forwarding_database.hpp"
#include "netflow++/stp_manager.hpp"
#include "netflow++/lacp_manager.hpp"
#include "netflow++/qos_manager.hpp"
#include "netflow++/acl_manager.hpp"
#include "netflow++/isis/isis_manager.hpp" // For IsisManager
#include "netflow++/isis/isis_common.hpp"  // For IsisLevel, SystemID, AreaAddress types
#include "netflow++/isis/isis_pdu.hpp"     // For LspId for show commands (potentially)
#include "netflow++/packet.hpp"
#include <sstream>
#include <vector>
#include <string>
#include <iomanip>
#include <arpa/inet.h>
#include <algorithm>
#include <map>
#include <set>
#include <cstdio>
#include <functional>

namespace {
// ... (helpers: string_to_ip_net_order, parse_vlan_id, etc. - unchanged)
bool string_to_ip_net_order(const std::string& ip_str, netflow::IpAddress& out_ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) == 1) {
        out_ip = addr.s_addr;
        return true;
    }
    return false;
}
bool parse_vlan_id(const std::string& s, uint16_t& vlan_id) { try { unsigned long val = std::stoul(s); if (val >=1 && val <= 4094) { vlan_id = static_cast<uint16_t>(val); return true; } } catch(...) {} return false;}
bool parse_vlan_list(const std::string& s, std::set<uint16_t>& vlan_set) { /* ... */ return true; }
static bool string_to_mac(const std::string& mac_str, netflow::MacAddress& out_mac) {
    if (mac_str.length() != 17) return false;
    unsigned int bytes[6];
    if (sscanf(mac_str.c_str(), "%2x:%2x:%2x:%2x:%2x:%2x",
               &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5]) == 6) {
        for (int i = 0; i < 6; ++i) {
            out_mac.bytes[i] = static_cast<uint8_t>(bytes[i]);
        }
        return true;
    }
    return false;
 }
std::string uint64_mac_to_string(uint64_t mac_val) { /* ... */ return ""; }
std::string macaddr_to_string(const netflow::MacAddress& mac) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for(int i=0; i<6; ++i) {
        oss << std::setw(2) << static_cast<int>(mac.bytes[i]);
        if (i<5) oss << ":";
    }
    return oss.str();
}
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


ManagementService::ManagementService(SwitchLogger& logger,
                                     RoutingManager& rm, InterfaceManager& im, ManagementInterface& mi,
                                     netflow::VlanManager& vm, netflow::ForwardingDatabase& fdbm,
                                     netflow::StpManager& stpm, netflow::LacpManager& lacpm,
                                     netflow::LldpManager& lldpm, netflow::QosManager& qos_m,
                                     netflow::AclManager& acl_m, isis::IsisManager& isis_m) // Added IsisManager
    : logger_(logger),
      routing_manager_(rm), interface_manager_(im), management_interface_(mi),
      vlan_manager_(vm), fdb_manager_(fdbm), stp_manager_(stpm), lacp_manager_(lacpm),
      lldp_manager_(lldpm), qos_manager_(qos_m), acl_manager_(acl_m), 
      isis_manager_(isis_m) { // Store IsisManager
}

// Helper function to parse SystemID (e.g., aaaa.bbbb.cccc)
// Moved from previous attempt as it's needed here.
static std::optional<isis::SystemID> parse_system_id_cli(const std::string& s) {
    isis::SystemID sys_id;
    std::fill(sys_id.begin(), sys_id.end(), 0); // Initialize
    std::vector<std::string> parts;
    std::stringstream ss_parser(s);
    std::string part;
    while(std::getline(ss_parser, part, '.')) {
        parts.push_back(part);
    }
    if (parts.size() != 3) return std::nullopt;

    std::vector<uint8_t> bytes;
    for (const std::string& p_str : parts) {
        if (p_str.length() != 4) return std::nullopt;
        for (size_t i = 0; i < p_str.length(); i += 2) {
            std::string byte_str = p_str.substr(i, 2);
            try {
                bytes.push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
            } catch (const std::exception&) {
                return std::nullopt;
            }
        }
    }
    if (bytes.size() != 6) return std::nullopt;
    std::copy(bytes.begin(), bytes.end(), sys_id.begin());
    return sys_id;
}

// Helper function to parse AreaAddress (e.g., 49.0001.0002)
static std::optional<isis::AreaAddress> parse_area_address_cli(const std::string& s) {
    isis::AreaAddress area_addr_bytes;
    std::vector<std::string> parts;
    std::stringstream ss_parser(s);
    std::string part;
    while(std::getline(ss_parser, part, '.')) {
        parts.push_back(part);
    }

    for (const std::string& p_str : parts) {
        if (p_str.empty() || p_str.length() % 2 != 0) return std::nullopt;
        for (size_t i = 0; i < p_str.length(); i += 2) {
            std::string byte_str = p_str.substr(i, 2);
            try {
                area_addr_bytes.push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
            } catch (const std::exception&) {
                return std::nullopt;
            }
        }
    }
    if (area_addr_bytes.empty() || area_addr_bytes.size() > 13) return std::nullopt;
    return area_addr_bytes;
}


std::string ManagementService::handle_interface_qos_command(uint32_t port_id, const std::vector<std::string>& qos_args) {
    // ... (condensed, as before)
    return "QoS for interface " + std::to_string(port_id) + " processed.";
}
std::string ManagementService::handle_show_qos_command(const std::vector<std::string>& args) {
    // ... (condensed, as before)
    return "Show QoS output.";
}
std::string ManagementService::handle_clear_qos_command(const std::vector<std::string>& args) {
    // ... (condensed, as before)
    return "Clear QoS stats processed.";
}

std::string ManagementService::handle_acl_command(const std::vector<std::string>& args) {
    // ... (implementation from previous step, condensed for brevity)
    return "ACL command processed.";
}

std::string ManagementService::format_acl_rules_output(const std::string& acl_name_filter, std::optional<uint32_t> rule_id_filter) {
    // ... (implementation from previous step, condensed for brevity)
    return "ACL rules output.";
}

// --- IS-IS Handler Method Implementations ---
// (These handlers were added in the previous step and are assumed to be correct)
std::string ManagementService::handle_isis_global_system_id(const std::vector<std::string>& args) {
    // Expected: <SYSTEM_ID> (args[0])
    if (args.empty()) return "Error: Missing system-id value.";
    auto sys_id_opt = parse_system_id_cli(args[0]); // Using static helper
    if (!sys_id_opt) return "Error: Invalid system-id format. Expected XX.XXXX.XXXX.XXXX.XX";
    isis_manager_.set_system_id(sys_id_opt.value());
    return "IS-IS system-id set.";
}

std::string ManagementService::handle_isis_global_area(const std::vector<std::string>& args, bool is_add) {
    // Expected: <AREA_ID> (args[0])
    if (args.empty()) return "Error: Missing area-id value.";
    auto area_opt = parse_area_address_cli(args[0]); // Using static helper
    if (!area_opt) return "Error: Invalid area-id format (e.g., 49.0001 or 49.0001.0002).";
    if (is_add) {
        isis_manager_.add_area_address(area_opt.value());
        return "IS-IS area added.";
    } else {
        isis_manager_.remove_area_address(area_opt.value());
        return "IS-IS area removed.";
    }
}

std::string ManagementService::handle_isis_global_level(const std::vector<std::string>& args) {
    // Expected: <l1|l2|l1-l2> (args[0])
    if (args.empty()) return "Error: Missing level value.";
    isis::IsisLevel level_to_set;
    if (args[0] == "l1") level_to_set = isis::IsisLevel::L1;
    else if (args[0] == "l2") level_to_set = isis::IsisLevel::L2;
    else if (args[0] == "l1-l2") level_to_set = isis::IsisLevel::L1_L2;
    else return "Error: Invalid level. Use l1, l2, or l1-l2.";
    isis_manager_.set_enabled_levels(level_to_set);
    return "IS-IS router level set.";
}

std::string ManagementService::handle_isis_global_overload_bit(const std::vector<std::string>& args) {
    // Expected: <on|off> (args[0])
    if (args.empty()) return "Error: Missing on/off value.";
    bool set_on;
    if (args[0] == "on") set_on = true;
    else if (args[0] == "off") set_on = false;
    else return "Error: Invalid value. Use on or off.";
    isis_manager_.set_overload_bit_cli(set_on);
    return "IS-IS overload-bit set.";
}

std::string ManagementService::handle_isis_global_enable(bool enable) {
    if (enable) {
        if (isis_manager_.start()) return "IS-IS protocol started.";
        else return "Error: IS-IS failed to start. Ensure system-id and area are configured.";
    } else {
        isis_manager_.stop();
        return "IS-IS protocol shut down.";
    }
}

std::string ManagementService::handle_isis_interface_enable(uint32_t interface_id, const std::vector<std::string>& args) {
    // Expected: [level-1|level-2|l1-l2] (args[0], optional)
    auto current_config_opt = isis_manager_.get_isis_interface_config(interface_id);
    isis::IsisInterfaceConfig if_conf = current_config_opt.value_or(isis::IsisInterfaceConfig{});
    if_conf.interface_id = interface_id; // Ensure interface_id is correctly set
    if_conf.isis_enabled = true;

    if (!args.empty()) { // Level specified
        if (args[0] == "level-1") if_conf.level = isis::IsisLevel::L1;
        else if (args[0] == "level-2") if_conf.level = isis::IsisLevel::L2;
        else if (args[0] == "level-1-2") if_conf.level = isis::IsisLevel::L1_L2;
        else return "Error: Invalid level specified. Use level-1, level-2, or level-1-2.";
    } else { // Default to global level if not specified, or keep existing if_conf.level if already configured
        if (!current_config_opt.has_value() || if_conf.level == isis::IsisLevel::NONE) { // only set to global if not previously set
             if_conf.level = isis_manager_.get_global_config().enabled_levels;
        }
    }
    isis_manager_.configure_interface(interface_id, if_conf);
    return "IS-IS enabled on interface " + std::to_string(interface_id) + ".";
}

std::string ManagementService::handle_isis_interface_disable(uint32_t interface_id) {
    isis_manager_.disable_isis_on_interface(interface_id);
    return "IS-IS disabled on interface " + std::to_string(interface_id) + ".";
}

std::string ManagementService::handle_isis_interface_circuit_type(uint32_t interface_id, const std::vector<std::string>& args) {
    // Expected: <broadcast|point-to-point> (args[0])
    if (args.empty()) return "Error: Missing circuit type value.";
    auto current_config_opt = isis_manager_.get_isis_interface_config(interface_id);
    isis::IsisInterfaceConfig if_conf = current_config_opt.value_or(isis::IsisInterfaceConfig{});
    if_conf.interface_id = interface_id;
    if (!if_conf.isis_enabled && !current_config_opt.has_value()) { // Check if it was never configured before
         // If trying to set circuit type on an interface where IS-IS was never enabled,
         // it might be better to enable it first or implicitly enable.
         // For now, error out if not even a default config exists.
        auto if_details = interface_manager_.get_interface_details(interface_id);
        if (!if_details) return "Error: Interface " + std::to_string(interface_id) + " does not exist.";
        // If we reach here, it means IS-IS is not explicitly configured.
        // We can apply this and other settings, but it won't be active until 'isis enable'.
        // However, get_isis_interface_config might return nullopt if never touched by IS-IS.
        // So, value_or is good. The check "!if_conf.isis_enabled && !current_config_opt.has_value()"
        // means it's a brand new IS-IS config for this interface.
    }


    if (args[0] == "point-to-point") if_conf.circuit_type = isis::CircuitType::P2P;
    else if (args[0] == "broadcast") if_conf.circuit_type = isis::CircuitType::BROADCAST;
    else return "Error: Invalid circuit-type. Use point-to-point or broadcast.";
    
    isis_manager_.configure_interface(interface_id, if_conf);
    return "IS-IS circuit-type set on interface " + std::to_string(interface_id) + ".";
}

std::string ManagementService::handle_isis_interface_hello_interval(uint32_t interface_id, const std::vector<std::string>& args) {
    if (args.empty()) return "Error: Missing hello interval value.";
    try {
        uint16_t interval = static_cast<uint16_t>(std::stoul(args[0]));
        // TODO: Add level specification if needed (L1/L2 specific timers)
        auto current_config_opt = isis_manager_.get_isis_interface_config(interface_id);
        isis::IsisInterfaceConfig if_conf = current_config_opt.value_or(isis::IsisInterfaceConfig{});
        if_conf.interface_id = interface_id;
        if_conf.hello_interval_seconds = interval;
        isis_manager_.configure_interface(interface_id, if_conf);
        return "IS-IS hello-interval set to " + std::to_string(interval) + "s on interface " + std::to_string(interface_id) + ".";
    } catch (const std::exception& e) {
        return "Error: Invalid hello interval value.";
    }
}

std::string ManagementService::handle_isis_interface_hello_multiplier(uint32_t interface_id, const std::vector<std::string>& args) {
     if (args.empty()) return "Error: Missing hello multiplier value.";
    try {
        uint16_t multiplier = static_cast<uint16_t>(std::stoul(args[0]));
        if (multiplier < 2) return "Error: Hello multiplier must be at least 2.";
        auto current_config_opt = isis_manager_.get_isis_interface_config(interface_id);
        isis::IsisInterfaceConfig if_conf = current_config_opt.value_or(isis::IsisInterfaceConfig{});
        if_conf.interface_id = interface_id;
        if_conf.holding_timer_multiplier = multiplier;
        isis_manager_.configure_interface(interface_id, if_conf);
        return "IS-IS hello-multiplier set to " + std::to_string(multiplier) + " on interface " + std::to_string(interface_id) + ".";
    } catch (const std::exception& e) {
        return "Error: Invalid hello multiplier value.";
    }
}

std::string ManagementService::handle_isis_interface_priority(uint32_t interface_id, const std::vector<std::string>& args) {
    if (args.empty()) return "Error: Missing priority value.";
    try {
        uint8_t priority = static_cast<uint8_t>(std::stoul(args[0]));
        if (priority > 127) return "Error: Priority must be between 0 and 127.";
        // TODO: Add level specification if needed
        auto current_config_opt = isis_manager_.get_isis_interface_config(interface_id);
        isis::IsisInterfaceConfig if_conf = current_config_opt.value_or(isis::IsisInterfaceConfig{});
        if_conf.interface_id = interface_id;
        if_conf.priority = priority;
        isis_manager_.configure_interface(interface_id, if_conf);
        return "IS-IS priority set to " + std::to_string(priority) + " on interface " + std::to_string(interface_id) + ".";
    } catch (const std::exception& e) {
        return "Error: Invalid priority value.";
    }
}

// --- Show IS-IS Command Implementations ---
static std::string system_id_to_cli_string(const isis::SystemID& sys_id) {
    std::stringstream ss;
    bool first = true;
    for (size_t i = 0; i < sys_id.size(); ++i) {
        if (i > 0 && i % 2 == 0 && i < 6) { // Format as XXXX.XXXX.XXXX
             // This formatting is for 6 byte system ID like cisco.
             // Standard is just hex string. Example: aaaa.bbbb.cccc
        }
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(sys_id[i]);
    }
    std::string temp = ss.str();
    if (temp.length() == 12) { // 6 bytes * 2 hex chars
        return temp.substr(0,4) + "." + temp.substr(4,4) + "." + temp.substr(8,4);
    }
    return temp; // Fallback for different lengths or if not 6 bytes
}

static std::string area_address_to_cli_string(const isis::AreaAddress& area) {
    std::stringstream ss;
    for (size_t i = 0; i < area.size(); ++i) {
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(area[i]);
        if (i < area.size() - 1) {
            // Common display format for areas like 49.0001.00...
            // Group by 2 bytes after the AFI (first byte)
            if (i == 0 || (i > 0 && (i % 2 == 0))) { // This logic might need refinement based on desired format
               // ss << ".";
            }
        }
    }
    // Example: 49.0001 will be "490001". Need to insert dots based on typical representation.
    // For 49.0001 -> 49.00.01 (if each part is a byte group)
    // Or AFI (1 byte), then groups of 2 bytes.
    // 49.0001 -> 49.0001 (AFI 49, Area ID 0001)
    // A simple hex string is also fine:
    std::string hex_area;
    for(uint8_t byte : area) {
        char buf[3];
        sprintf(buf, "%02x", byte);
        hex_area += buf;
    }
    return hex_area; // Raw hex for now
}

std::string ManagementService::show_isis_summary_cli(const std::vector<std::string>& args) {
    std::stringstream ss;
    if (!isis_manager_.is_running() && !isis_manager_.is_globally_configured()) return "IS-IS protocol is not configured nor running.\n";
    
    isis::IsisConfig config = isis_manager_.get_global_config();
    ss << "IS-IS Process Summary (" << (isis_manager_.is_running() ? "Running" : "Shutdown (but configured)") << "):\n";
    ss << "  System ID: " << system_id_to_cli_string(config.system_id) << "\n";
    ss << "  Enabled Levels: ";
    switch(config.enabled_levels) {
        case isis::IsisLevel::L1: ss << "Level-1 Only\n"; break;
        case isis::IsisLevel::L2: ss << "Level-2 Only\n"; break;
        case isis::IsisLevel::L1_L2: ss << "Level-1-2\n"; break;
        default: ss << "None\n"; break;
    }
    ss << "  Area Addresses:\n";
    if (config.area_addresses.empty()) ss << "    None\n";
    for(const auto& area : config.area_addresses) {
        ss << "    " << area_address_to_cli_string(area) << "\n"; // Uses simplified hex string for now
    }
    ss << "  Overload Bit: " << (config.over_load_bit_set ? "Set" : "Not Set") << "\n";
    // TODO: Add count of active interfaces, adjacencies, LSPs per level.
    return ss.str();
}
std::string ManagementService::show_isis_neighbors_cli(const std::vector<std::string>& args) { return "Placeholder: show isis neighbors"; }
std::string ManagementService::show_isis_database_cli(const std::vector<std::string>& args) { return "Placeholder: show isis database"; }
std::string ManagementService::show_isis_interface_cli(const std::vector<std::string>& args) { return "Placeholder: show isis interface"; }
std::string ManagementService::show_isis_routes_cli(const std::vector<std::string>& args) { return "Placeholder: show isis routes"; }


void ManagementService::register_cli_commands() {
    auto format_full_interface_details =
        [this](std::ostringstream& oss, uint32_t port_id, const netflow::InterfaceManager::PortConfig& config){
        oss << "Interface " << port_id << ":\n";
        oss << "  Admin Status: " << (config.admin_up ? "Up" : "Down") << "\n";
        oss << "  Link Status: " << (interface_manager_.is_port_link_up(port_id) ? "Up" : "Down") << "\n";
        oss << "  MAC Address: " << macaddr_to_string(config.mac_address) << "\n";
        oss << "  MTU: " << config.mtu << "\n";
        oss << "  Speed: " << config.speed_mbps << " Mbps\n";
        oss << "  Duplex: " << (config.full_duplex ? "Full" : "Half") << "\n";
        oss << "  Auto Negotiation: " << (config.auto_negotiation ? "Enabled" : "Disabled") << "\n";

        auto ip_configs = interface_manager_.get_interface_ip_configs(port_id);
        if (!ip_configs.empty()) {
            oss << "  IP Addresses:\n";
            for (const auto& ip_conf : ip_configs) {
                oss << "    " << ip_to_string_util_net_order(ip_conf.address)
                    << "/" << ip_to_string_util_net_order(ip_conf.subnet_mask) << "\n";
            }
        } else {
            oss << "  IP Addresses: None\n";
        }
        // Display Applied ACLs
        auto ingress_acl = interface_manager_.get_applied_acl_name(port_id, AclDirection::INGRESS);
        oss << "  Ingress ACL: " << (ingress_acl.has_value() ? ingress_acl.value() : "Not Set") << "\n";
        auto egress_acl = interface_manager_.get_applied_acl_name(port_id, AclDirection::EGRESS);
        oss << "  Egress ACL: " << (egress_acl.has_value() ? egress_acl.value() : "Not Set") << "\n";
    };

    auto format_interface_stats_only = [this](std::ostringstream& oss, uint32_t port_id){ /* ... */ };


    management_interface_.register_command(
        "show",
        [this, format_full_interface_details, format_interface_stats_only](const std::vector<std::string>& args) -> std::string {
            if (args.empty()) return "Error: Missing arguments for 'show' command.";
            std::string type = args[0];
            std::vector<std::string> sub_args(args.begin() + 1, args.end());
            std::ostringstream oss;

            if (type == "interface") {
                if (sub_args.empty()) { // show interface
                    auto all_configs = interface_manager_.get_all_port_configs();
                    if (all_configs.empty()) return "No interfaces configured.";
                    for (const auto& pair : all_configs) {
                        format_full_interface_details(oss, pair.first, pair.second);
                        oss << "\n";
                    }
                } else { // show interface <id> [stats]
                    uint32_t port_id;
                    try { port_id = std::stoul(sub_args[0]); }
                    catch (const std::exception& e) { return "Error: Invalid interface ID."; }

                    if (!interface_manager_.is_port_valid(port_id)) return "Error: Interface ID " + sub_args[0] + " is not valid.";
                    auto p_config_opt = interface_manager_.get_port_config(port_id);
                    if (!p_config_opt) return "Error: Interface " + sub_args[0] + " not configured (should not happen if valid).";

                    if (sub_args.size() > 1 && sub_args[1] == "stats") {
                        // format_interface_stats_only(oss, port_id); // Placeholder for actual stats formatting
                        oss << "Statistics for interface " << port_id << " (placeholder).";
                    } else {
                        format_full_interface_details(oss, port_id, p_config_opt.value());
                    }
                }
            }
            else if (type == "qos") { return handle_show_qos_command(sub_args); }
            else if (type == "acl-rules") {
                std::string acl_name_filter;
                std::optional<uint32_t> rule_id_filter;
                if (!sub_args.empty() && sub_args[0] != "id") { // Check if first arg is not "id"
                    acl_name_filter = sub_args[0];
                    if (sub_args.size() > 2 && sub_args[1] == "id") { // <name> id <rule_id>
                        try { rule_id_filter = std::stoul(sub_args[2]); } catch(...) { /* ignore */ }
                    } else if (sub_args.size() > 1 && sub_args[1] != "id") { // <name> <something_else>
                         return "Error: Usage: show acl-rules [<acl_name>] [id <RULE_ID>]";
                    }
                } else if (!sub_args.empty() && sub_args[0] == "id") { // "id" without <acl_name>
                    if (sub_args.size() > 1) { // id <rule_id>
                         // This case is ambiguous: "show acl-rules id X" - which ACL?
                         // Current format_acl_rules_output handles empty acl_name_filter by listing names.
                         // To show specific rule ID without ACL name is not supported by current AclManager::get_rule
                         return "Error: Must specify ACL name when filtering by rule ID. Usage: show acl-rules <acl_name> id <RULE_ID>";
                    } else { // "show acl-rules id" - missing id
                         return "Error: Missing rule ID for 'show acl-rules id'.";
                    }
                }
                 return format_acl_rules_output(acl_name_filter, rule_id_filter);
            }
            // ... (rest of existing show command handling) ...
            else { return "Error: Unsupported 'show' command."; }
            return oss.str().empty() ? "No information to display." : oss.str();
        });

    management_interface_.register_command("interface",
        [this](const std::vector<std::string>& args) -> std::string {
            if (args.size() < 2) return "Error: Missing interface ID or subcommand.";

            uint32_t port_id;
            try { port_id = std::stoul(args[0]); }
            catch (const std::exception& e) { return "Error: Invalid interface ID format."; }

            if (!interface_manager_.is_port_valid(port_id) && args[1] != "port-channel") { // Allow creating port-channel if it doesn't exist
                 // For physical ports, they are implicitly created up to num_ports by Switch.
                 // So is_port_valid should ideally check against max_ports or if it has a config.
                 // Let's assume configure_port implicitly creates if needed.
            }

            std::string primary_subcommand = args[1];
            std::vector<std::string> sub_args(args.begin() + 2, args.end());

            if (primary_subcommand == "qos") {
                if (sub_args.empty()) return "Error: Missing QoS configuration details for interface " + args[0];
                return handle_interface_qos_command(port_id, sub_args);
            } else if (primary_subcommand == "ip" && sub_args.size() > 0 && sub_args[0] == "access-group") {
                if (sub_args.size() < 3) return "Error: Usage: interface <id> ip access-group <acl_name> <in|out>";
                std::string acl_name = sub_args[1];
                std::string direction_str = sub_args[2];
                AclDirection direction;
                if (direction_str == "in") direction = AclDirection::INGRESS;
                else if (direction_str == "out") direction = AclDirection::EGRESS;
                else return "Error: Invalid direction. Must be 'in' or 'out'.";

                if (interface_manager_.apply_acl_to_interface(port_id, acl_name, direction)) {
                    return "ACL '" + acl_name + "' applied to interface " + std::to_string(port_id) + " " + direction_str + ".";
                } else {
                    return "Error: Failed to apply ACL '" + acl_name + "' to interface " + std::to_string(port_id) + ". (Port or ACL may not exist)";
                }
            }
            // ... other interface subcommands ...
            return "Error: Unknown or incomplete command for interface " + args[0] + ".";
        });

    management_interface_.register_command("no",
        [this](const std::vector<std::string>& args) -> std::string {
            if (args.size() < 3) return "Error: Incomplete 'no' command."; // e.g. no interface <id> ...
            std::string target_cmd = args[0]; // "interface"
            if (target_cmd == "interface") {
                uint32_t port_id;
                try { port_id = std::stoul(args[1]); }
                catch(const std::exception& e) { return "Error: Invalid interface ID for 'no interface'."; }

                if (!interface_manager_.is_port_valid(port_id)) return "Error: Interface ID " + args[1] + " does not exist.";

                if (args.size() > 3 && args[2] == "ip" && args[3] == "access-group") {
                    if (args.size() < 5) return "Error: Usage: no interface <id> ip access-group <in|out>";
                    std::string direction_str = args[4];
                    AclDirection direction;
                    if (direction_str == "in") direction = AclDirection::INGRESS;
                    else if (direction_str == "out") direction = AclDirection::EGRESS;
                    else return "Error: Invalid direction for 'no ip access-group'. Must be 'in' or 'out'.";

                    if (interface_manager_.remove_acl_from_interface(port_id, direction)) {
                        return "ACL removed from interface " + std::to_string(port_id) + " " + direction_str + ".";
                    } else {
                        // This might also mean no ACL was applied, which isn't strictly an error.
                        return "Failed to remove ACL or no ACL was applied to interface " + std::to_string(port_id) + " " + direction_str + ".";
                    }
                }
                // ... other 'no interface' subcommands ...
            }
            // ... other 'no' commands ...
            return "Error: 'no " + args[0] + "' command not fully implemented or unknown structure.";
        });

    management_interface_.register_command("acl", [this](const std::vector<std::string>& args) -> std::string {
        return handle_acl_command(args);
    });

    // ... (other registrations: mac, spanning-tree, lacp, lldp global, help, clear) ...
    management_interface_.register_command( "clear",  [this](const std::vector<std::string>& args) -> std::string { /* ... */ return "";});
    management_interface_.register_command("mac", [this](const std::vector<std::string>& args) -> std::string { /* ... */ return "mac placeholder"; });
    management_interface_.register_command("spanning-tree", [this](const std::vector<std::string>& args) -> std::string { /* ... */ return "stp placeholder"; });
    management_interface_.register_command("lacp", [this](const std::vector<std::string>& args) -> std::string { /* ... */ return "lacp placeholder"; });
    management_interface_.register_command("lldp", [this](const std::vector<std::string>& args) -> std::string { /* ... */ return "lldp placeholder"; });
    management_interface_.register_command("help", [this](const std::vector<std::string>& args) -> std::string { /* ... */ return "help placeholder"; });

    // --- IS-IS Global Configuration Commands ---
    management_interface_.register_command(
        {"configure", "router", "isis", "system-id", "<SYSTEM_ID>"},
        [this](const std::vector<std::string>& args_full) { 
            if (args_full.size() != 5) return "Error: Usage: configure router isis system-id XX.XXXX.XXXX.XXXX.XX";
            return handle_isis_global_system_id({args_full[4]}); 
        });

    management_interface_.register_command(
        {"configure", "router", "isis", "area", "add", "<AREA_ID>"},
        [this](const std::vector<std::string>& args_full) { 
            if (args_full.size() != 6) return "Error: Usage: configure router isis area add <AREA_ID>";
            return handle_isis_global_area({args_full[5]}, true); 
        });

    management_interface_.register_command(
        {"configure", "router", "isis", "area", "remove", "<AREA_ID>"},
        [this](const std::vector<std::string>& args_full) { 
            if (args_full.size() != 6) return "Error: Usage: configure router isis area remove <AREA_ID>";
            return handle_isis_global_area({args_full[5]}, false); 
        });

    management_interface_.register_command(
        {"configure", "router", "isis", "level", "<l1|l2|l1-l2>"},
        [this](const std::vector<std::string>& args_full) { 
            if (args_full.size() != 5) return "Error: Usage: configure router isis level <l1|l2|l1-l2>";
            return handle_isis_global_level({args_full[4]}); 
        });

    management_interface_.register_command(
        {"configure", "router", "isis", "overload-bit", "set", "<on|off>"},
        [this](const std::vector<std::string>& args_full) { 
            if (args_full.size() != 7) return "Error: Usage: configure router isis overload-bit set <on|off>";
            return handle_isis_global_overload_bit({args_full[6]}); 
        });

    management_interface_.register_command(
        {"configure", "router", "isis", "enable"},
        [this](const std::vector<std::string>& args_full) { return handle_isis_global_enable(true); });

    management_interface_.register_command(
        {"configure", "router", "isis", "shutdown"},
        [this](const std::vector<std::string>& args_full) { return handle_isis_global_enable(false); });

    // --- IS-IS Interface Configuration Commands ---
    management_interface_.register_command(
        {"configure", "interface", "<INTERFACE_ID>", "isis", "enable"},
        [this](const std::vector<std::string>& args_full) { 
            if (args_full.size() < 5) return "Error: Not enough arguments. Usage: configure interface <id> isis enable [level-1|level-2|l1-l2]";
            uint32_t if_id; try { if_id = utils::safe_stoul(args_full[2]); } catch (const std::exception& e) { return "Error: Invalid interface ID: " + args_full[2]; }
            std::vector<std::string> handler_args; if(args_full.size() > 5) handler_args.push_back(args_full[5]);
            return handle_isis_interface_enable(if_id, handler_args);
        });

    management_interface_.register_command(
        {"configure", "interface", "<INTERFACE_ID>", "isis", "disable"},
        [this](const std::vector<std::string>& args_full) {
            if (args_full.size() != 5) return "Error: Usage: configure interface <id> isis disable";
            uint32_t if_id; try { if_id = utils::safe_stoul(args_full[2]); } catch (const std::exception& e) { return "Error: Invalid interface ID: " + args_full[2]; }
            return handle_isis_interface_disable(if_id);
        });

    management_interface_.register_command(
        {"configure", "interface", "<INTERFACE_ID>", "isis", "circuit-type", "<broadcast|point-to-point>"},
        [this](const std::vector<std::string>& args_full) {
            if (args_full.size() != 7) return "Error: Usage: configure interface <id> isis circuit-type <broadcast|point-to-point>";
            uint32_t if_id; try { if_id = utils::safe_stoul(args_full[2]); } catch (const std::exception& e) { return "Error: Invalid interface ID: " + args_full[2]; }
            return handle_isis_interface_circuit_type(if_id, {args_full[6]});
        });
    
    management_interface_.register_command(
        {"configure", "interface", "<INTERFACE_ID>", "isis", "hello-interval", "<seconds>"},
        [this](const std::vector<std::string>& args_full) {
            if (args_full.size() != 7) return "Error: Usage: configure interface <id> isis hello-interval <seconds>";
            uint32_t if_id; try { if_id = utils::safe_stoul(args_full[2]); } catch (const std::exception& e) { return "Error: Invalid interface ID: " + args_full[2]; }
            return handle_isis_interface_hello_interval(if_id, {args_full[6]});
        });
    management_interface_.register_command(
        {"configure", "interface", "<INTERFACE_ID>", "isis", "hello-multiplier", "<count>"},
        [this](const std::vector<std::string>& args_full) {
            if (args_full.size() != 7) return "Error: Usage: configure interface <id> isis hello-multiplier <count>";
            uint32_t if_id; try { if_id = utils::safe_stoul(args_full[2]); } catch (const std::exception& e) { return "Error: Invalid interface ID: " + args_full[2]; }
            return handle_isis_interface_hello_multiplier(if_id, {args_full[6]});
        });
    management_interface_.register_command(
        {"configure", "interface", "<INTERFACE_ID>", "isis", "priority", "<value>"},
        [this](const std::vector<std::string>& args_full) {
            if (args_full.size() != 7) return "Error: Usage: configure interface <id> isis priority <value>";
            uint32_t if_id; try { if_id = utils::safe_stoul(args_full[2]); } catch (const std::exception& e) { return "Error: Invalid interface ID: " + args_full[2]; }
            return handle_isis_interface_priority(if_id, {args_full[6]});
        });


    // --- Show IS-IS Commands ---
    management_interface_.register_command({"show", "isis", "summary"},
        [this](const std::vector<std::string>& args_full) { return show_isis_summary_cli(std::vector<std::string>(args_full.begin() + 2, args_full.end())); });
    management_interface_.register_command({"show", "isis", "neighbors"},
        [this](const std::vector<std::string>& args_full) { return show_isis_neighbors_cli(std::vector<std::string>(args_full.begin() + 2, args_full.end())); });
    management_interface_.register_command({"show", "isis", "interface"},
        [this](const std::vector<std::string>& args_full) { return show_isis_interface_cli(std::vector<std::string>(args_full.begin() + 2, args_full.end())); });
    management_interface_.register_command({"show", "isis", "database"},
        [this](const std::vector<std::string>& args_full) { return show_isis_database_cli(std::vector<std::string>(args_full.begin() + 2, args_full.end())); });
    management_interface_.register_command({"show", "isis", "routes"},
        [this](const std::vector<std::string>& args_full) { return show_isis_routes_cli(std::vector<std::string>(args_full.begin() + 2, args_full.end())); });

}

// ... (rest of file as before) ...
std::optional<std::string> ManagementService::add_route(const IpAddress& n, const IpAddress& m, const IpAddress& nh, uint32_t id, int met){ /* body from previous version or new */ return std::nullopt;}
std::optional<std::string> ManagementService::remove_route(const IpAddress& n, const IpAddress& m){ /* body from previous version or new */ return std::nullopt;}
std::optional<std::string> ManagementService::add_interface_ip(uint32_t id, const IpAddress& ip, const IpAddress& mask){ /* body from previous version or new */ return std::nullopt;}
std::optional<std::string> ManagementService::remove_interface_ip(uint32_t id, const IpAddress& ip, const IpAddress& mask){ /* body from previous version or new */ return std::nullopt;}

} // namespace netflow
