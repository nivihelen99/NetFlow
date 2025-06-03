#ifndef NETFLOW_MANAGEMENT_SERVICE_HPP
#define NETFLOW_MANAGEMENT_SERVICE_HPP

#include "netflow++/routing_manager.hpp"
#include "netflow++/interface_manager.hpp"
#include "netflow++/management_interface.hpp"
#include "netflow++/vlan_manager.hpp"
#include "netflow++/forwarding_database.hpp"
#include "netflow++/stp_manager.hpp"
#include "netflow++/lacp_manager.hpp"
#include "netflow++/lldp_manager.hpp"
#include "netflow++/qos_manager.hpp"
#include "netflow++/acl_manager.hpp"
#include "netflow++/logger.hpp"
#include "netflow++/packet.hpp"            // For IpAddress
#include "netflow++/isis/isis_manager.hpp" // Include IsisManager header

#include <string>     // For std::string
#include <vector>     // For std::vector
#include <optional>   // For std::optional
#include <sstream>    // For std::stringstream
#include <cstdint>    // For uint32_t etc.

namespace netflow {

class ManagementService {
public:
    // Constructor with types correctly namespaced
    ManagementService(SwitchLogger& logger,
                      RoutingManager& rm, 
                      InterfaceManager& im, 
                      ManagementInterface& mi,
                      netflow::VlanManager& vm, // netflow:: is fine, not redundant
                      netflow::ForwardingDatabase& fdbm, // netflow:: is fine
                      netflow::StpManager& stpm,         // netflow:: is fine
                      netflow::LacpManager& lacpm,       // netflow:: is fine
                      netflow::LldpManager& lldpm,     // netflow:: is fine
                      netflow::QosManager& qos_m,       // netflow:: is fine
                      netflow::AclManager& acl_m,       // netflow:: is fine
                      netflow::isis::IsisManager& isis_m); // Correctly netflow::isis::

    void register_cli_commands();

    std::optional<std::string> add_route(
        const IpAddress& network,
        const IpAddress& mask,
        const IpAddress& next_hop,
        uint32_t interface_id,
        int metric = 1);

    std::optional<std::string> remove_route(
        const IpAddress& network,
        const IpAddress& mask);

    std::optional<std::string> add_interface_ip(
        uint32_t interface_id,
        const IpAddress& ip_address,
        const IpAddress& subnet_mask);

    std::optional<std::string> remove_interface_ip(
        uint32_t interface_id,
        const IpAddress& ip_address,
        const IpAddress& subnet_mask);

private:
    // Member variables with types correctly namespaced
    SwitchLogger& logger_;
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
    netflow::isis::IsisManager& isis_manager_; // Correctly netflow::isis::

    // CLI Handler function declarations
    std::string handle_interface_qos_command(uint32_t port_id, const std::vector<std::string>& qos_args);
    std::string handle_show_qos_command(const std::vector<std::string>& args);
    std::string handle_clear_qos_command(const std::vector<std::string>& args);

    std::string handle_acl_command(const std::vector<std::string>& args);
    std::string format_acl_rules_output(const std::string& acl_name_filter, std::optional<uint32_t> rule_id_filter);

    std::string handle_isis_global_system_id(const std::vector<std::string>& args);
    std::string handle_isis_global_area(const std::vector<std::string>& args, bool is_add);
    std::string handle_isis_global_level(const std::vector<std::string>& args);
    std::string handle_isis_global_overload_bit(const std::vector<std::string>& args);
    std::string handle_isis_global_enable(bool enable);

    std::string handle_isis_interface_enable(uint32_t interface_id, const std::vector<std::string>& args);
    std::string handle_isis_interface_disable(uint32_t interface_id);
    std::string handle_isis_interface_circuit_type(uint32_t interface_id, const std::vector<std::string>& args);
    std::string handle_isis_interface_hello_interval(uint32_t interface_id, const std::vector<std::string>& args);
    std::string handle_isis_interface_hello_multiplier(uint32_t interface_id, const std::vector<std::string>& args);
    std::string handle_isis_interface_priority(uint32_t interface_id, const std::vector<std::string>& args);

    std::string show_isis_neighbors_cli(const std::vector<std::string>& args);
    std::string show_isis_database_cli(const std::vector<std::string>& args);
    std::string show_isis_interface_cli(const std::vector<std::string>& args);
    std::string show_isis_routes_cli(const std::vector<std::string>& args);
    std::string show_isis_summary_cli(const std::vector<std::string>& args);
};

} // namespace netflow

#endif // NETFLOW_MANAGEMENT_SERVICE_HPP
