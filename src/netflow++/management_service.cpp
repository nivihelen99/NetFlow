#include "netflow++/management_service.hpp"
#include "netflow++/interface_manager.hpp" // Included for types like InterfaceManager::PortConfig, netflow::AclDirection
#include "netflow++/vlan_manager.hpp"      // Included for VlanManager type
#include "netflow++/forwarding_database.hpp" // Included for ForwardingDatabase type
#include "netflow++/stp_manager.hpp"       // Included for StpManager type
#include "netflow++/lacp_manager.hpp"      // Included for LacpManager and related types
#include "netflow++/qos_manager.hpp"       // Included for QosManager type, SchedulerType
#include "netflow++/acl_manager.hpp"       // Included for AclManager, AclRule, AclActionType
#include "netflow++/isis/isis_manager.hpp" // For netflow::isis::IsisManager
#include "netflow++/isis/isis_common.hpp"  // For netflow::isis::IsisLevel, SystemID, AreaAddress, SYSTEM_ID_LENGTH
#include "netflow++/isis/isis_pdu.hpp"     // For PDU types if needed by CLI show commands
#include "netflow++/packet.hpp"            // For IpAddress, MacAddress
#include "netflow++/utils.hpp"             // For utility functions

#include <sstream>    // For std::ostringstream, std::istringstream
#include <vector>     // For std::vector
#include <string>     // For std::string, std::to_string
#include <iomanip>    // For std::hex, std::setfill, std::setw
#include <arpa/inet.h> // For inet_pton, inet_ntoa (used in helpers)
#include <algorithm>  // For std::transform, std::find_if etc. (general utility)
#include <map>        // For std::map (general utility)
#include <set>        // For std::set (used in vlan list parsing helper)
#include <cstdio>     // For sscanf (used in string_to_mac helper)
#include <functional> // For std::function (though ManagementInterface handles this)
#include <stdexcept>  // For std::exception in stoul/stoi try-catch blocks

// Anonymous namespace for local helper functions
namespace {

// string_to_mac helper used by some CLI commands if needed
static bool string_to_mac_local(const std::string& mac_str, netflow::MacAddress& out_mac) {
    if (mac_str.length() != 17) return false;
    unsigned int bytes[6];
    if (sscanf(mac_str.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
               &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5]) == 6) {
        for (int i = 0; i < 6; ++i) {
            if (bytes[i] > 0xFF) return false;
            out_mac.bytes[i] = static_cast<uint8_t>(bytes[i]);
        }
        return true;
    }
    return false;
}

// macaddr_to_string helper used by some CLI commands
std::string macaddr_to_string_local(const netflow::MacAddress& mac) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        oss << std::setw(2) << static_cast<int>(mac.bytes[i]);
        if (i < 5) oss << ":";
    }
    return oss.str();
}

// Helper function to parse SystemID (e.g., aaaa.bbbb.cccc)
static std::optional<netflow::isis::SystemID> parse_system_id_cli(const std::string& s) {
    netflow::isis::SystemID sys_id;
    std::fill(sys_id.begin(), sys_id.end(), 0);
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
        for (std::size_t i = 0; i < p_str.length(); i += 2) {
            std::string byte_str = p_str.substr(i, 2);
            auto byte_val_opt = netflow::utils::safe_stoul("0x" + byte_str);
            if (!byte_val_opt || *byte_val_opt > 255) return std::nullopt;
            bytes.push_back(static_cast<uint8_t>(*byte_val_opt));
        }
    }
    if (bytes.size() != netflow::isis::SYSTEM_ID_LENGTH) return std::nullopt;
    std::copy(bytes.begin(), bytes.end(), sys_id.begin());
    return sys_id;
}

// Helper function to parse AreaAddress (e.g., 49.0001.0002)
static std::optional<netflow::isis::AreaAddress> parse_area_address_cli(const std::string& s) {
    netflow::isis::AreaAddress area_addr_bytes;
    std::vector<std::string> parts;
    std::stringstream ss_parser(s);
    std::string part;
    
    if (s.find('.') != std::string::npos) {
        while(std::getline(ss_parser, part, '.')) {
            parts.push_back(part);
        }
    } else {
        if (s.length() % 2 != 0 || s.empty() || s.length() > 40) return std::nullopt; // Max 20 bytes = 40 hex
        for (std::size_t i = 0; i < s.length(); i += 2) {
            parts.push_back(s.substr(i,2));
        }
    }
    
    if (parts.empty()) return std::nullopt;

    for (const std::string& p_str : parts) {
        // If original string had no dots, p_str are 2-char hex strings.
        // If original had dots, p_str can be longer, e.g. "0001". Ensure these are even length.
        if (p_str.length() % 2 != 0 ) return std::nullopt; 
        
        for (std::size_t i = 0; i < p_str.length(); i += 2) {
            std::string byte_str = p_str.substr(i, 2);
            auto byte_val_opt = netflow::utils::safe_stoul("0x" + byte_str);
            if (!byte_val_opt || *byte_val_opt > 255) return std::nullopt;
            area_addr_bytes.push_back(static_cast<uint8_t>(*byte_val_opt));
        }
    }
    // Max AreaAddress size check (e.g. up to 20 for NSAP like)
    if (area_addr_bytes.empty() || area_addr_bytes.size() > 20) return std::nullopt; 
    return area_addr_bytes;
}

static std::string system_id_to_cli_string(const netflow::isis::SystemID& sys_id) {
    // Format as XXXX.XXXX.XXXX
    std::string temp = netflow::utils::to_hex_string(sys_id, '\0');
    if (temp.length() == 12) { 
        return temp.substr(0,4) + "." + temp.substr(4,4) + "." + temp.substr(8,4);
    }
    return temp; 
}

static std::string area_address_to_cli_string(const netflow::isis::AreaAddress& area) {
    // Format as XX.XXXX.XXXX...
    if (area.empty()) return "";
    std::string result = netflow::utils::to_hex_string({area[0]}, '\0');
    if (area.size() > 1) {
        for (std::size_t i = 1; i < area.size(); ++i) {
            if ((i-1) % 2 == 0) result += ".";
            char buf[3];
            sprintf(buf, "%02x", area[i]);
            result += buf;
        }
    }
    return result;
}

} // namespace

namespace netflow {

// Constructor definition
ManagementService::ManagementService(SwitchLogger& logger,
                                     RoutingManager& rm, 
                                     InterfaceManager& im, 
                                     ManagementInterface& mi,
                                     netflow::VlanManager& vm, 
                                     netflow::ForwardingDatabase& fdbm,
                                     netflow::StpManager& stpm, 
                                     netflow::LacpManager& lacpm,
                                     netflow::LldpManager& lldpm, 
                                     netflow::QosManager& qos_m,
                                     netflow::AclManager& acl_m, 
                                     netflow::isis::IsisManager& isis_m)
    : logger_(logger),
      routing_manager_(rm), 
      interface_manager_(im), 
      management_interface_(mi),
      vlan_manager_(vm), 
      fdb_manager_(fdbm), 
      stp_manager_(stpm), 
      lacp_manager_(lacpm),
      lldp_manager_(lldpm), 
      qos_manager_(qos_m), 
      acl_manager_(acl_m),
      isis_manager_(isis_m) {
}

std::optional<std::string> netflow::ManagementService::add_route(
    const IpAddress& network, const IpAddress& mask, const IpAddress& next_hop,
    uint32_t interface_id, int metric) {
    routing_manager_.add_static_route(network, mask, next_hop, interface_id, metric);
    return std::nullopt;
}

std::optional<std::string> netflow::ManagementService::remove_route(
    const IpAddress& network, const IpAddress& mask) {
    routing_manager_.remove_static_route(network, mask);
    return std::nullopt;
}

std::optional<std::string> netflow::ManagementService::add_interface_ip(
    uint32_t interface_id, const IpAddress& ip_address, const IpAddress& subnet_mask) {
    interface_manager_.add_ip_address(interface_id, ip_address, subnet_mask);
    return std::nullopt;
}

std::optional<std::string> netflow::ManagementService::remove_interface_ip(
    uint32_t interface_id, const IpAddress& ip_address, const IpAddress& subnet_mask) {
    interface_manager_.remove_ip_address(interface_id, ip_address, subnet_mask);
    return std::nullopt;
}

std::string netflow::ManagementService::handle_interface_qos_command(uint32_t port_id, const std::vector<std::string>& qos_args) {
    if (qos_args.empty()) return "Error: No QoS parameters specified.";
    QosConfig new_config;
    std::string scheduler_str = qos_args[0];
    if (scheduler_str == "strict-priority") new_config.scheduler = SchedulerType::STRICT_PRIORITY;
    else if (scheduler_str == "wrr") new_config.scheduler = SchedulerType::WEIGHTED_ROUND_ROBIN;
    else if (scheduler_str == "drr") new_config.scheduler = SchedulerType::DEFICIT_ROUND_ROBIN;
    else return "Error: Unknown scheduler type '" + scheduler_str + "'. Use strict-priority, wrr, or drr.";

    std::size_t current_arg_idx = 1; // Use std::size_t
    while(current_arg_idx < qos_args.size()) {
        const std::string& param = qos_args[current_arg_idx];
        if (param == "queues" && current_arg_idx + 1 < qos_args.size()) {
            auto num_q = utils::safe_stoul(qos_args[++current_arg_idx]);
            if (!num_q || *num_q == 0 || *num_q > 8) return "Error: Invalid number of queues (must be 1-8).";
            new_config.num_queues = static_cast<uint8_t>(*num_q);
        } else if (param == "depth" && current_arg_idx + 1 < qos_args.size()) {
            auto depth = utils::safe_stoul(qos_args[++current_arg_idx]);
            if (!depth || *depth == 0 || *depth > 65535) return "Error: Invalid max queue depth.";
            new_config.max_queue_depth = static_cast<uint32_t>(*depth);
        } else if (param == "weights" && new_config.scheduler != SchedulerType::STRICT_PRIORITY) {
            new_config.queue_weights.clear();
            for (uint8_t i = 0; i < new_config.num_queues; ++i) {
                if (++current_arg_idx < qos_args.size()) {
                    auto weight = utils::safe_stoul(qos_args[current_arg_idx]);
                    if (!weight || *weight == 0) return "Error: Invalid queue weight (must be >0).";
                    new_config.queue_weights.push_back(static_cast<uint32_t>(*weight));
                } else return "Error: Insufficient weight values provided for queues.";
            }
        } else if (param == "rate") {
             new_config.rate_limits_kbps.clear();
            for (uint8_t i = 0; i < new_config.num_queues; ++i) {
                if (++current_arg_idx < qos_args.size()) {
                    auto rate = utils::safe_stoul(qos_args[current_arg_idx]);
                     // Allow 0 for unlimited, check for parse failure if safe_stoul returns nullopt for non-numeric
                    if (!rate && qos_args[current_arg_idx] != "0") return "Error: Invalid rate limit value. Must be a number or 0 for unlimited.";
                    new_config.rate_limits_kbps.push_back(rate ? static_cast<uint32_t>(*rate) : 0);
                } else return "Error: Insufficient rate limit values provided for queues.";
            }
        } else {
            return "Error: Unknown QoS parameter '" + param + "' or missing value.";
        }
        current_arg_idx++;
    }
    new_config.validate_and_prepare();
    qos_manager_.configure_port_qos(port_id, new_config);
    return "QoS configuration applied to interface " + std::to_string(port_id) + ".";
}

std::string netflow::ManagementService::handle_show_qos_command(const std::vector<std::string>& args) {
    std::ostringstream oss;
    if (args.empty() || args[0] != "interface" || args.size() < 2) {
        oss << "Error: Usage: show qos interface <interface_id>\n";
        return oss.str();
    }
    auto if_id_opt = utils::safe_stoul(args[1]);
    if (!if_id_opt) return "Error: Invalid interface ID '" + args[1] + "'.";
    uint32_t port_id = static_cast<uint32_t>(*if_id_opt);

    auto qos_config_opt = qos_manager_.get_port_qos_config(port_id);
    if (!qos_config_opt) {
        return "No QoS configuration found for interface " + std::to_string(port_id) + ".\n";
    }
    const auto& config = qos_config_opt.value();
    oss << "QoS Configuration for Interface " << port_id << ":\n";
    oss << "  Scheduler: ";
    switch(config.scheduler) {
        case SchedulerType::STRICT_PRIORITY: oss << "Strict Priority\n"; break;
        case SchedulerType::WEIGHTED_ROUND_ROBIN: oss << "Weighted Round Robin\n"; break;
        case SchedulerType::DEFICIT_ROUND_ROBIN: oss << "Deficit Round Robin\n"; break;
        default: oss << "Unknown\n"; break;
    }
    oss << "  Number of Queues: " << static_cast<int>(config.num_queues) << "\n";
    oss << "  Max Queue Depth (per queue): " << config.max_queue_depth << " packets\n";
    
    if (config.scheduler != SchedulerType::STRICT_PRIORITY && !config.queue_weights.empty()) {
        oss << "  Queue Weights: ";
        for (std::size_t i = 0; i < config.queue_weights.size(); ++i) {
            oss << config.queue_weights[i] << (i == config.queue_weights.size() - 1 ? "" : " ");
        }
        oss << "\n";
    }
    if (!config.rate_limits_kbps.empty()) {
        oss << "  Rate Limits (kbps): ";
        for (std::size_t i = 0; i < config.rate_limits_kbps.size(); ++i) {
            oss << (config.rate_limits_kbps[i] == 0 ? "Unlimited" : std::to_string(config.rate_limits_kbps[i])) 
                << (i == config.rate_limits_kbps.size() - 1 ? "" : " ");
        }
        oss << "\n";
    }
    oss << "  Queue Statistics:\n";
    oss << "    ID | Enqueued | Dequeued | Dropped(Full) | Dropped(NoCfg) | Current Depth\n";
    oss << "    ---|----------|----------|---------------|----------------|---------------\n";
    for (uint8_t q_id = 0; q_id < config.num_queues; ++q_id) {
        auto stats_opt = qos_manager_.get_queue_stats(port_id, q_id);
        if (stats_opt) {
            const auto& s = stats_opt.value();
            oss << std::setw(5) << static_cast<int>(q_id) << " | "
                << std::setw(8) << s.packets_enqueued << " | "
                << std::setw(8) << s.packets_dequeued << " | "
                << std::setw(13) << s.packets_dropped_full << " | "
                << std::setw(14) << s.packets_dropped_no_config << " | "
                << std::setw(13) << s.current_depth << "\n";
        } else {
            oss << std::setw(5) << static_cast<int>(q_id) << " | " << "Statistics not available.\n";
        }
    }
    return oss.str();
}

std::string netflow::ManagementService::handle_clear_qos_command(const std::vector<std::string>& args) {
    if (args.empty() || args[0] != "interface" || args.size() < 2) {
        return "Error: Usage: clear qos interface <interface_id> [stats]";
    }
    return "Placeholder: QoS statistics cleared for interface (functionality to be added to QosManager).\n";
}

std::string netflow::ManagementService::handle_acl_command(const std::vector<std::string>& args) {
    if (args.empty()) return "Error: Missing ACL subcommand. Usage: acl <create|delete|add-rule|remove-rule|clear-rules> ...";
    const std::string& subcommand = args[0];

    if (subcommand == "create") {
        if (args.size() < 2) return "Error: Usage: acl create <acl_name>";
        if (acl_manager_.create_acl(args[1])) return "ACL '" + args[1] + "' created.";
        else return "Error: ACL '" + args[1] + "' already exists or invalid name.";
    } else if (subcommand == "delete") {
        if (args.size() < 2) return "Error: Usage: acl delete <acl_name>";
        if (acl_manager_.delete_acl(args[1])) return "ACL '" + args[1] + "' deleted.";
        else return "Error: ACL '" + args[1] + "' not found.";
    } else if (subcommand == "add-rule") {
        if (args.size() < 8) return "Error: Insufficient arguments for 'acl add-rule'. Minimum: acl add-rule <name> rule <id> priority <prio> action <type>";
        const std::string& acl_name = args[1];
        if (args[2] != "rule") return "Error: Expected 'rule' keyword.";
        auto rule_id_opt = utils::safe_stoul(args[3]);
        if (!rule_id_opt) return "Error: Invalid rule ID.";
        if (args[4] != "priority") return "Error: Expected 'priority' keyword.";
        auto priority_opt = utils::safe_stoi(args[5]);
        if (!priority_opt) return "Error: Invalid priority value.";
        if (args[6] != "action") return "Error: Expected 'action' keyword.";
        
        AclRule rule(static_cast<uint32_t>(*rule_id_opt), *priority_opt, AclActionType::DENY);
        std::string action_str = args[7];
        if (action_str == "permit") rule.action = AclActionType::PERMIT;
        else if (action_str == "deny") rule.action = AclActionType::DENY;
        else return "Error: Invalid action. Use 'permit' or 'deny'.";
        
        if (acl_manager_.add_rule(acl_name, rule)) return "Rule " + args[3] + " added to ACL '" + acl_name + "'.";
        else return "Error: Failed to add rule to ACL '" + acl_name + "'.";
    } else if (subcommand == "remove-rule") {
        if (args.size() < 4 || args[2] != "rule") return "Error: Usage: acl remove-rule <acl_name> rule <rule_id>";
        auto rule_id_opt = utils::safe_stoul(args[3]);
        if (!rule_id_opt) return "Error: Invalid rule ID.";
        if (acl_manager_.remove_rule(args[1], static_cast<uint32_t>(*rule_id_opt))) return "Rule " + args[3] + " removed from ACL '" + args[1] + "'.";
        else return "Error: Rule " + args[3] + " not found in ACL '" + args[1] + "'.";
    } else if (subcommand == "clear-rules") {
        if (args.size() < 2) return "Error: Usage: acl clear-rules <acl_name>";
        acl_manager_.clear_rules(args[1]);
        return "All rules cleared from ACL '" + args[1] + "'.";
    }
    return "Error: Unknown ACL subcommand '" + subcommand + "'.";
}

std::string netflow::ManagementService::format_acl_rules_output(const std::string& acl_name_filter, std::optional<uint32_t> rule_id_filter) {
    std::ostringstream oss;
    auto all_acls = acl_manager_.get_all_named_acls();
    if (all_acls.empty()) return "No ACLs configured.\n";

    for (const auto& acl_pair : all_acls) {
        if (!acl_name_filter.empty() && acl_pair.first != acl_name_filter) {
            continue;
        }
        oss << "ACL: " << acl_pair.first << "\n";
        if (acl_pair.second.empty()) {
            oss << "  No rules.\n";
        } else {
            for (const auto& rule : acl_pair.second) {
                if (rule_id_filter.has_value() && rule.rule_id != rule_id_filter.value()) {
                    continue;
                }
                oss << "  Rule ID: " << rule.rule_id << ", Priority: " << rule.priority;
                oss << ", Action: ";
                switch (rule.action) {
                    case AclActionType::PERMIT: oss << "Permit"; break;
                    case AclActionType::DENY: oss << "Deny"; break;
                    case AclActionType::REDIRECT: oss << "Redirect"; 
                        if(rule.redirect_port_id) oss << " to port " << rule.redirect_port_id.value();
                        break;
                }
                if(rule.src_mac) oss << ", SrcMAC: " << macaddr_to_string_local(rule.src_mac.value());
                if(rule.dst_mac) oss << ", DstMAC: " << macaddr_to_string_local(rule.dst_mac.value());
                if(rule.ethertype) oss << ", Ethertype: 0x" << std::hex << rule.ethertype.value() << std::dec;
                oss << "\n";
            }
        }
        oss << "\n";
        if (!acl_name_filter.empty() && rule_id_filter.has_value()) {
            break;
        }
    }
    if (oss.str().empty()) {
        if (!acl_name_filter.empty() && rule_id_filter.has_value()) {
            return "Rule ID " + std::to_string(rule_id_filter.value()) + " not found in ACL '" + acl_name_filter + "'.\n";
        } else if (!acl_name_filter.empty()) {
            return "ACL '" + acl_name_filter + "' not found or has no rules matching filter.\n";
        }
        return "No ACLs or rules matching filter.\n";
    }
    return oss.str();
}

std::string netflow::ManagementService::handle_isis_global_system_id(const std::vector<std::string>& args) {
    if (args.empty()) return "Error: Missing system-id value.";
    auto sys_id_opt = parse_system_id_cli(args[0]); 
    if (!sys_id_opt) return "Error: Invalid system-id format. Expected XXXX.XXXX.XXXX";
    isis_manager_.set_system_id(sys_id_opt.value()); 
    return "IS-IS system-id set.";
}

std::string netflow::ManagementService::handle_isis_global_area(const std::vector<std::string>& args, bool is_add) {
    if (args.empty()) return "Error: Missing area-id value.";
    auto area_opt = parse_area_address_cli(args[0]); 
    if (!area_opt) return "Error: Invalid area-id format (e.g., 49.0001 or 49.0001.0002).";
    if (is_add) {
        isis_manager_.add_area_address(area_opt.value()); 
        return "IS-IS area added.";
    } else {
        isis_manager_.remove_area_address(area_opt.value()); 
        return "IS-IS area removed.";
    }
}

std::string netflow::ManagementService::handle_isis_global_level(const std::vector<std::string>& args) {
    if (args.empty()) return "Error: Missing level value.";
    netflow::isis::IsisLevel level_to_set;
    if (args[0] == "l1") level_to_set = netflow::isis::IsisLevel::L1;
    else if (args[0] == "l2") level_to_set = netflow::isis::IsisLevel::L2;
    else if (args[0] == "l1-l2") level_to_set = netflow::isis::IsisLevel::L1_L2;
    else return "Error: Invalid level. Use l1, l2, or l1-l2.";
    isis_manager_.set_enabled_levels(level_to_set); 
    return "IS-IS router level set.";
}

std::string netflow::ManagementService::handle_isis_global_overload_bit(const std::vector<std::string>& args) {
    if (args.empty()) return "Error: Missing on/off value.";
    bool set_on;
    if (args[0] == "on") set_on = true;
    else if (args[0] == "off") set_on = false;
    else return "Error: Invalid value. Use on or off.";
    isis_manager_.set_overload_bit_cli(set_on); 
    return "IS-IS overload-bit set.";
}

std::string netflow::ManagementService::handle_isis_global_enable(bool enable) {
    if (enable) {
        if (isis_manager_.start()) return "IS-IS protocol started."; 
        else return "Error: IS-IS failed to start. Ensure system-id and area are configured.";
    } else {
        isis_manager_.stop(); 
        return "IS-IS protocol shut down.";
    }
}

std::string netflow::ManagementService::handle_isis_interface_enable(uint32_t interface_id, const std::vector<std::string>& args) {
    auto current_config_opt = isis_manager_.get_isis_interface_config(interface_id); 
    netflow::isis::IsisInterfaceConfig if_conf = current_config_opt.value_or(netflow::isis::IsisInterfaceConfig{});
    if_conf.interface_id = interface_id; 
    if_conf.isis_enabled = true;

    if (!args.empty()) { 
        if (args[0] == "level-1") if_conf.level = netflow::isis::IsisLevel::L1;
        else if (args[0] == "level-2") if_conf.level = netflow::isis::IsisLevel::L2;
        else if (args[0] == "level-1-2") if_conf.level = netflow::isis::IsisLevel::L1_L2;
        else return "Error: Invalid level specified. Use level-1, level-2, or level-1-2.";
    } else { 
        if (!current_config_opt.has_value() || if_conf.level == netflow::isis::IsisLevel::NONE) { 
             if_conf.level = isis_manager_.get_global_config().enabled_levels; 
        }
    }
    isis_manager_.configure_interface(interface_id, if_conf); 
    return "IS-IS enabled on interface " + std::to_string(interface_id) + ".";
}

std::string netflow::ManagementService::handle_isis_interface_disable(uint32_t interface_id) {
    isis_manager_.disable_isis_on_interface(interface_id); 
    return "IS-IS disabled on interface " + std::to_string(interface_id) + ".";
}

std::string netflow::ManagementService::handle_isis_interface_circuit_type(uint32_t interface_id, const std::vector<std::string>& args) {
    if (args.empty()) return "Error: Missing circuit type value.";
    auto current_config_opt = isis_manager_.get_isis_interface_config(interface_id); 
    netflow::isis::IsisInterfaceConfig if_conf = current_config_opt.value_or(netflow::isis::IsisInterfaceConfig{});
    if_conf.interface_id = interface_id;
    if (!if_conf.isis_enabled && !current_config_opt.has_value()) { 
        auto port_config_opt = interface_manager_.get_port_config(interface_id);
        if (!port_config_opt) {
            return "Error: Interface with ID " + std::to_string(interface_id) + " not found.";
        }
    }

    if (args[0] == "point-to-point") if_conf.circuit_type = netflow::isis::CircuitType::P2P;
    else if (args[0] == "broadcast") if_conf.circuit_type = netflow::isis::CircuitType::BROADCAST;
    else return "Error: Invalid circuit-type. Use point-to-point or broadcast.";
    
    isis_manager_.configure_interface(interface_id, if_conf); 
    return "IS-IS circuit-type set on interface " + std::to_string(interface_id) + ".";
}

std::string netflow::ManagementService::handle_isis_interface_hello_interval(uint32_t interface_id, const std::vector<std::string>& args) {
    if (args.empty()) return "Error: Missing hello interval value.";
    std::optional<unsigned long> interval_opt = netflow::utils::safe_stoul(args[0]);
    if (!interval_opt || *interval_opt == 0 || *interval_opt > 65535) {
        return "Error: Invalid hello interval value. Must be 1-65535.";
    }
    uint16_t interval = static_cast<uint16_t>(*interval_opt);
    auto current_config_opt = isis_manager_.get_isis_interface_config(interface_id); 
    netflow::isis::IsisInterfaceConfig if_conf = current_config_opt.value_or(netflow::isis::IsisInterfaceConfig{});
    if_conf.interface_id = interface_id;
    if_conf.hello_interval_seconds = interval;
    isis_manager_.configure_interface(interface_id, if_conf); 
    return "IS-IS hello-interval set to " + std::to_string(interval) + "s on interface " + std::to_string(interface_id) + ".";
}

std::string netflow::ManagementService::handle_isis_interface_hello_multiplier(uint32_t interface_id, const std::vector<std::string>& args) {
    if (args.empty()) return "Error: Missing hello multiplier value.";
    std::optional<unsigned long> multiplier_opt = netflow::utils::safe_stoul(args[0]);
    if (!multiplier_opt || *multiplier_opt < 2 || *multiplier_opt > 255) {
        return "Error: Invalid hello multiplier value. Must be >= 2.";
    }
    uint16_t multiplier = static_cast<uint16_t>(*multiplier_opt);
    auto current_config_opt = isis_manager_.get_isis_interface_config(interface_id); 
    netflow::isis::IsisInterfaceConfig if_conf = current_config_opt.value_or(netflow::isis::IsisInterfaceConfig{});
    if_conf.interface_id = interface_id;
    if_conf.holding_timer_multiplier = multiplier;
    isis_manager_.configure_interface(interface_id, if_conf); 
    return "IS-IS hello-multiplier set to " + std::to_string(multiplier) + " on interface " + std::to_string(interface_id) + ".";
}

std::string netflow::ManagementService::handle_isis_interface_priority(uint32_t interface_id, const std::vector<std::string>& args) {
    if (args.empty()) return "Error: Missing priority value.";
    std::optional<unsigned long> priority_opt = netflow::utils::safe_stoul(args[0]);
    if (!priority_opt || *priority_opt > 127) {
        return "Error: Invalid priority value. Must be 0-127.";
    }
    uint8_t priority = static_cast<uint8_t>(*priority_opt);
    auto current_config_opt = isis_manager_.get_isis_interface_config(interface_id); 
    netflow::isis::IsisInterfaceConfig if_conf = current_config_opt.value_or(netflow::isis::IsisInterfaceConfig{});
    if_conf.interface_id = interface_id;
    if_conf.priority = priority;
    isis_manager_.configure_interface(interface_id, if_conf); 
    return "IS-IS priority set to " + std::to_string(priority) + " on interface " + std::to_string(interface_id) + ".";
}

std::string netflow::ManagementService::show_isis_summary_cli(const std::vector<std::string>& args) {
    std::ostringstream ss;
    if (!isis_manager_.is_running() && !isis_manager_.is_globally_configured()) return "IS-IS protocol is not configured nor running.\n"; 
    
    netflow::isis::IsisConfig config = isis_manager_.get_global_config(); 
    ss << "IS-IS Process Summary (" << (isis_manager_.is_running() ? "Running" : "Shutdown (but configured)") << "):\n"; 
    ss << "  System ID: " << system_id_to_cli_string(config.system_id) << "\n";
    ss << "  Enabled Levels: ";
    switch(config.enabled_levels) {
        case netflow::isis::IsisLevel::L1: ss << "Level-1 Only\n"; break;
        case netflow::isis::IsisLevel::L2: ss << "Level-2 Only\n"; break;
        case netflow::isis::IsisLevel::L1_L2: ss << "Level-1-2\n"; break;
        default: ss << "None\n"; break;
    }
    ss << "  Area Addresses:\n";
    if (config.area_addresses.empty()) ss << "    None\n";
    for(const auto& area : config.area_addresses) {
        ss << "    " << area_address_to_cli_string(area) << "\n"; 
    }
    ss << "  Overload Bit: " << (config.over_load_bit_set ? "Set" : "Not Set") << "\n";
    return ss.str();
}

std::string netflow::ManagementService::show_isis_neighbors_cli(const std::vector<std::string>& args) { return "Placeholder: show isis neighbors"; }
std::string netflow::ManagementService::show_isis_database_cli(const std::vector<std::string>& args) { return "Placeholder: show isis database"; }
std::string netflow::ManagementService::show_isis_interface_cli(const std::vector<std::string>& args) { return "Placeholder: show isis interface"; }
std::string netflow::ManagementService::show_isis_routes_cli(const std::vector<std::string>& args) { return "Placeholder: show isis routes"; }

void netflow::ManagementService::register_cli_commands() {
    management_interface_.register_command(
        {"show", "interface"},
        [this](const std::vector<std::string>& args) { 
            // Simplified: actual implementation would parse args for specific interface
            std::ostringstream oss;
            auto all_configs = this->interface_manager_.get_all_port_configs();
            if (all_configs.empty()) return std::string("No interfaces configured.");
            for (const auto& pair : all_configs) {
                 oss << "Interface " << pair.first << ": Admin " << (pair.second.admin_up ? "Up" : "Down") << "\n";
            }
            return oss.str();
        }
    );
    management_interface_.register_command(
        {"show", "qos", "interface"},
         [this](const std::vector<std::string>& args) { 
            if(args.empty()) return "Error: Missing interface ID for 'show qos interface'.";
            // Pass only the arguments intended for the handler (after "interface")
            return this->handle_show_qos_command({"interface", args[0]}); 
        }
    );
     management_interface_.register_command(
        {"show", "acl-rules"},
        [this](const std::vector<std::string>& args) {
            std::string acl_name_filter;
            std::optional<uint32_t> rule_id_filter;
            if (!args.empty() && args[0] != "id") {
                acl_name_filter = args[0];
                if (args.size() > 2 && args[1] == "id") {
                    try { rule_id_filter = static_cast<uint32_t>(std::stoul(args[2])); } catch(...) { /* ignore */ }
                } else if (args.size() > 1 && args[1] != "id") {
                     return "Error: Usage: show acl-rules [<acl_name>] [id <RULE_ID>]";
                }
            } else if (args.size() > 1 && args[0] == "id") {
                 return "Error: Must specify ACL name when filtering by rule ID. Usage: show acl-rules <acl_name> id <RULE_ID>";
            } else if (args.size() == 1 && args[0] == "id") {
                 return "Error: Missing rule ID for 'show acl-rules id'.";
            }
            return this->format_acl_rules_output(acl_name_filter, rule_id_filter);
        }
    );

    management_interface_.register_command(
        {"interface", "<IF_ID>", "qos"}, // This is a key for registration, not directly for parsing
        [this](const std::vector<std::string>& args) { // args here are those *after* the matched key prefix
            if (args.size() < 2) return "Error: Interface ID and QoS config needed."; // args[0] is IF_ID, args[1]... is qos_args
            uint32_t if_id;
            try { if_id = static_cast<uint32_t>(std::stoul(args[0])); }
            catch(const std::exception& e) { return "Error: Invalid interface ID: " + args[0]; }
            return this->handle_interface_qos_command(if_id, std::vector<std::string>(args.begin() + 1, args.end()));
        }
    );
    management_interface_.register_command(
        {"interface", "<IF_ID>", "ip", "access-group", "<ACL_NAME>", "<in|out>"},
        [this](const std::vector<std::string>& args) { // args are <IF_ID_val>, ip, access-group, <ACL_NAME_val>, <in|out_val>
            if (args.size() != 5) return "Error: Usage: interface <id> ip access-group <acl_name> <in|out>";
            uint32_t if_id;
            try { if_id = static_cast<uint32_t>(std::stoul(args[0])); }
            catch(const std::exception& e) { return "Error: Invalid interface ID: " + args[0]; }
            
            const std::string& acl_name = args[3];
            const std::string& direction_str = args[4];
            netflow::AclDirection direction;
            if (direction_str == "in") direction = netflow::AclDirection::INGRESS;
            else if (direction_str == "out") direction = netflow::AclDirection::EGRESS;
            else return "Error: Invalid direction. Must be 'in' or 'out'.";
            
            if (this->interface_manager_.apply_acl_to_interface(if_id, acl_name, direction)) {
                 return "ACL '" + acl_name + "' applied to interface " + std::to_string(if_id) + " " + direction_str + ".";
            }
            return "Error: Failed to apply ACL '" + acl_name + "' to interface " + std::to_string(if_id) + ".";
        }
    );
     management_interface_.register_command(
        {"no", "interface", "<IF_ID>", "ip", "access-group", "<in|out>"},
        [this](const std::vector<std::string>& args) {
            if (args.size() != 5) return "Error: Usage: no interface <id> ip access-group <in|out>";
            uint32_t if_id;
            try { if_id = static_cast<uint32_t>(std::stoul(args[1])); } // args[0] is "<IF_ID>", args[1] is actual ID
            catch(const std::exception& e) { return "Error: Invalid interface ID: " + args[1]; }
            
            const std::string& direction_str = args[4]; // args[4] is <in|out_val>
            netflow::AclDirection direction;
            if (direction_str == "in") direction = netflow::AclDirection::INGRESS;
            else if (direction_str == "out") direction = netflow::AclDirection::EGRESS;
            else return "Error: Invalid direction. Must be 'in' or 'out'.";

            if (this->interface_manager_.remove_acl_from_interface(if_id, direction)) {
                 return "ACL removed from interface " + std::to_string(if_id) + " " + direction_str + ".";
            }
            return "Error: Failed to remove ACL or no ACL applied on interface " + std::to_string(if_id) + " " + direction_str + ".";
        }
    );
     management_interface_.register_command(
        {"acl"}, 
        [this](const std::vector<std::string>& args) -> std::string {
            return this->handle_acl_command(args);
        }
    );

    // IS-IS Commands
    management_interface_.register_command(
        {"configure", "router", "isis", "system-id"}, 
        [this](const std::vector<std::string>& args) { return this->handle_isis_global_system_id(args); });
    management_interface_.register_command(
        {"configure", "router", "isis", "area", "add"},
        [this](const std::vector<std::string>& args) { return this->handle_isis_global_area(args, true); });
    management_interface_.register_command(
        {"configure", "router", "isis", "area", "remove"},
        [this](const std::vector<std::string>& args) { return this->handle_isis_global_area(args, false); });
    management_interface_.register_command(
        {"configure", "router", "isis", "level"},
        [this](const std::vector<std::string>& args) { return this->handle_isis_global_level(args); });
    management_interface_.register_command(
        {"configure", "router", "isis", "overload-bit", "set"},
        [this](const std::vector<std::string>& args) { return this->handle_isis_global_overload_bit(args); });
    management_interface_.register_command(
        {"configure", "router", "isis", "enable"},
        [this](const std::vector<std::string>& args) { return this->handle_isis_global_enable(true); });
    management_interface_.register_command(
        {"configure", "router", "isis", "shutdown"},
        [this](const std::vector<std::string>& args) { return this->handle_isis_global_enable(false); });

    management_interface_.register_command(
        {"configure", "interface", "isis", "enable"}, 
        [this](const std::vector<std::string>& args) { 
            if (args.empty()) return "Error: Missing interface ID.";
            uint32_t if_id; try { if_id = static_cast<uint32_t>(std::stoul(args[0])); } 
            catch (const std::exception& e) { return "Error: Invalid interface ID: " + args[0]; }
            return this->handle_isis_interface_enable(if_id, std::vector<std::string>(args.begin() + 1, args.end()));
        });
    management_interface_.register_command(
        {"configure", "interface", "isis", "disable"}, 
        [this](const std::vector<std::string>& args) {
            if (args.empty()) return "Error: Missing interface ID.";
            uint32_t if_id; try { if_id = static_cast<uint32_t>(std::stoul(args[0])); } 
            catch (const std::exception& e) { return "Error: Invalid interface ID: " + args[0]; }
            return this->handle_isis_interface_disable(if_id);
        });
    management_interface_.register_command(
        {"configure", "interface", "isis", "circuit-type"}, 
        [this](const std::vector<std::string>& args) {
            if (args.size() < 2) return "Error: Missing interface ID or circuit type.";
            uint32_t if_id; try { if_id = static_cast<uint32_t>(std::stoul(args[0])); } 
            catch (const std::exception& e) { return "Error: Invalid interface ID: " + args[0]; }
            return this->handle_isis_interface_circuit_type(if_id, {args[1]});
        });
    management_interface_.register_command(
        {"configure", "interface", "isis", "hello-interval"}, 
        [this](const std::vector<std::string>& args) {
            if (args.size() < 2) return "Error: Missing interface ID or interval.";
            uint32_t if_id; try { if_id = static_cast<uint32_t>(std::stoul(args[0])); } 
            catch (const std::exception& e) { return "Error: Invalid interface ID: " + args[0]; }
            return this->handle_isis_interface_hello_interval(if_id, {args[1]});
        });
    management_interface_.register_command(
        {"configure", "interface", "isis", "hello-multiplier"}, 
        [this](const std::vector<std::string>& args) {
            if (args.size() < 2) return "Error: Missing interface ID or multiplier.";
            uint32_t if_id; try { if_id = static_cast<uint32_t>(std::stoul(args[0])); } 
            catch (const std::exception& e) { return "Error: Invalid interface ID: " + args[0]; }
            return this->handle_isis_interface_hello_multiplier(if_id, {args[1]});
        });
    management_interface_.register_command(
        {"configure", "interface", "isis", "priority"}, 
        [this](const std::vector<std::string>& args) {
            if (args.size() < 2) return "Error: Missing interface ID or priority.";
            uint32_t if_id; try { if_id = static_cast<uint32_t>(std::stoul(args[0])); } 
            catch (const std::exception& e) { return "Error: Invalid interface ID: " + args[0]; }
            return this->handle_isis_interface_priority(if_id, {args[1]});
        });

    management_interface_.register_command({"show", "isis", "summary"},
        [this](const std::vector<std::string>& args) { return this->show_isis_summary_cli(args); });
    management_interface_.register_command({"show", "isis", "neighbors"},
        [this](const std::vector<std::string>& args) { return this->show_isis_neighbors_cli(args); });
    management_interface_.register_command({"show", "isis", "interface"},
        [this](const std::vector<std::string>& args) { return this->show_isis_interface_cli(args); });
    management_interface_.register_command({"show", "isis", "database"},
        [this](const std::vector<std::string>& args) { return this->show_isis_database_cli(args); });
    management_interface_.register_command({"show", "isis", "routes"},
        [this](const std::vector<std::string>& args) { return this->show_isis_routes_cli(args); });
}

} // namespace netflow
