#ifndef NETFLOW_MANAGEMENT_SERVICE_HPP
#define NETFLOW_MANAGEMENT_SERVICE_HPP

#include "netflow++/routing_manager.hpp"
#include "netflow++/interface_manager.hpp" // For interface validation
#include "netflow++/management_interface.hpp"
#include "netflow++/vlan_manager.hpp"
#include "netflow++/forwarding_database.hpp"
#include "netflow++/stp_manager.hpp"
#include "netflow++/lacp_manager.hpp"
#include "netflow++/lldp_manager.hpp"      // Added LldpManager include
#include "netflow++/qos_manager.hpp"       // Include QosManager header
#include "netflow++/acl_manager.hpp"       // Include AclManager header
#include "netflow++/logger.hpp"            // Include Logger
#include "netflow++/packet.hpp"            // For IpAddress
#include <string>
#include <vector>    // Added for std::vector
#include <optional>
#include <sstream> // For formatting error messages

namespace netflow {

// Forward declare QosManager if full include isn't desired here,
// but since we will use its types in private methods, full include is fine.
// Removed forward declaration, will include the full header.
#include "netflow++/isis/isis_manager.hpp" // Include IsisManager header

class ManagementService {
public:
    ManagementService(SwitchLogger& logger, // Added logger
                      RoutingManager& rm, InterfaceManager& im, ManagementInterface& mi,
                      netflow::VlanManager& vm, netflow::ForwardingDatabase& fdbm,
                      netflow::StpManager& stpm, netflow::LacpManager& lacpm,
                      netflow::LldpManager& lldpm, netflow::QosManager& qos_m,
                      netflow::AclManager& acl_m, netflow::isis::IsisManager& isis_m); // Corrected namespace

    void register_cli_commands();

    // Returns error string on failure, std::nullopt on success
    std::optional<std::string> add_route(
        const IpAddress& network,
        const IpAddress& mask,
        const IpAddress& next_hop,
        uint32_t interface_id,
        int metric = 1);

    std::optional<std::string> remove_route(
        const IpAddress& network,
        const IpAddress& mask);

    // Interface IP configuration methods
    // Returns error string on failure, std::nullopt on success
    std::optional<std::string> add_interface_ip(
        uint32_t interface_id,
        const IpAddress& ip_address,
        const IpAddress& subnet_mask);

    std::optional<std::string> remove_interface_ip(
        uint32_t interface_id,
        const IpAddress& ip_address,
        const IpAddress& subnet_mask);

    // Placeholder for other management functions, e.g., showing ARP table
    // std::string show_arp_table() const;
    // std::string show_ip_interfaces() const;

private:
    RoutingManager& routing_manager_;
    InterfaceManager& interface_manager_;
    ManagementInterface& management_interface_;
    netflow::VlanManager& vlan_manager_;
    netflow::ForwardingDatabase& fdb_manager_;
    netflow::StpManager& stp_manager_;
    netflow::LacpManager& lacp_manager_;
    netflow::LldpManager& lldp_manager_;
    netflow::QosManager& qos_manager_;
    netflow::AclManager& acl_manager_;
    netflow::isis::IsisManager& isis_manager_; // Corrected namespace for member
    SwitchLogger& logger_; // Added logger member

    // QoS CLI Handlers
    std::string handle_interface_qos_command(uint32_t port_id, const std::vector<std::string>& qos_args);
    std::string handle_show_qos_command(const std::vector<std::string>& args);
    std::string handle_clear_qos_command(const std::vector<std::string>& args);

    // ACL CLI Handler (main dispatcher for 'acl' command)
    std::string handle_acl_command(const std::vector<std::string>& args);
    // Helper for formatting ACL output for 'show acl-rules'
    std::string format_acl_rules_output(const std::string& acl_name_filter, std::optional<uint32_t> rule_id_filter);
    // Show ACLs is handled within handle_show_command

    // IS-IS CLI Handlers (prototypes)
    // Global IS-IS configuration
    std::string handle_isis_global_system_id(const std::vector<std::string>& args);
    std::string handle_isis_global_area(const std::vector<std::string>& args, bool is_add); // bool to distinguish add/remove
    std::string handle_isis_global_level(const std::vector<std::string>& args);
    std::string handle_isis_global_overload_bit(const std::vector<std::string>& args);
    std::string handle_isis_global_enable(bool enable); // For global enable/disable (start/stop)

    // Interface IS-IS configuration
    std::string handle_isis_interface_enable(uint32_t interface_id, const std::vector<std::string>& args);
    std::string handle_isis_interface_disable(uint32_t interface_id);
    std::string handle_isis_interface_circuit_type(uint32_t interface_id, const std::vector<std::string>& args);
    std::string handle_isis_interface_hello_interval(uint32_t interface_id, const std::vector<std::string>& args);
    std::string handle_isis_interface_hello_multiplier(uint32_t interface_id, const std::vector<std::string>& args);
    std::string handle_isis_interface_priority(uint32_t interface_id, const std::vector<std::string>& args);
    // std::string handle_isis_interface_metric(uint32_t interface_id, const std::vector<std::string>& args); // If implemented

    // Show IS-IS commands
    std::string show_isis_neighbors_cli(const std::vector<std::string>& args);
    std::string show_isis_database_cli(const std::vector<std::string>& args);
    std::string show_isis_interface_cli(const std::vector<std::string>& args);
    std::string show_isis_routes_cli(const std::vector<std::string>& args);
    std::string show_isis_summary_cli(const std::vector<std::string>& args); // New summary show command

};

} // namespace netflow

#endif // NETFLOW_MANAGEMENT_SERVICE_HPP
