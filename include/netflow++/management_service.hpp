#ifndef NETFLOW_MANAGEMENT_SERVICE_HPP
#define NETFLOW_MANAGEMENT_SERVICE_HPP

#include "netflow++/routing_manager.hpp"
#include "netflow++/interface_manager.hpp" // For interface validation
#include "netflow++/packet.hpp"            // For IpAddress
#include <string>
#include <optional>
#include <sstream> // For formatting error messages

namespace netflow {

class ManagementService {
public:
    ManagementService(RoutingManager& rm, InterfaceManager& im);

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
};

} // namespace netflow

#endif // NETFLOW_MANAGEMENT_SERVICE_HPP
