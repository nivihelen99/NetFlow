#include "netflow++/management_service.hpp"

// For inet_ntoa or similar if used for logging/error messages (though IpAddress is uint32_t)
// For this implementation, we'll rely on to_string or manual formatting for IPs in messages if needed.
// packet.hpp should provide ntohl if needed for display formatting of IpAddress.
#if __has_include(<arpa/inet.h>)
#include <arpa/inet.h>
#elif __has_include(<winsock2.h>)
#include <winsock2.h>
#endif


namespace netflow {

ManagementService::ManagementService(RoutingManager& rm, InterfaceManager& im)
    : routing_manager_(rm), interface_manager_(im) {
    // Constructor body
}

std::optional<std::string> ManagementService::add_route(
    const IpAddress& network,
    const IpAddress& mask,
    const IpAddress& next_hop,
    uint32_t interface_id,
    int metric) {

    // Validate interface_id
    if (interface_id != 0 && !interface_manager_.is_port_valid(interface_id)) {
        // Assuming interface_id 0 might be special (e.g. null interface for blackhole, though not typical for static routes)
        // or that is_port_valid handles all valid interface types (physical, VLAN SVIs etc.)
        // If interface_id refers to a non-existent or non-L3-capable interface, this check helps.
        // For directly connected routes (next_hop is 0.0.0.0), interface_id is crucial.
        // For routes via a gateway, interface_id is also important for ARP source.
        std::ostringstream error_msg;
        error_msg << "Error: Invalid interface ID " << interface_id << ". Interface does not exist or is not configured.";
        return error_msg.str();
    }

    // Validate network address (ensure it's a network address, not a host address within the network)
    // The RoutingManager::add_static_route already performs (network & mask)
    // so this is more of a conceptual validation or for stricter input.
    // For example, if network is 192.168.1.1 and mask is 255.255.255.0, it should be 192.168.1.0.
    IpAddress calculated_network = network & mask;
    if (network != calculated_network) {
        // This warning/error helps user provide the canonical network address.
        // Depending on strictness, could auto-correct or return error.
        // For now, we'll proceed but one might log a warning.
        // If RoutingManager doesn't normalize, it should be done here.
        // Current RoutingManager normalizes it.
    }

    // Further validation: e.g., is next_hop on a directly connected subnet of interface_id?
    // This is more advanced validation and might be skipped for a basic service.
    // If next_hop is not 0.0.0.0, then interface_id should ideally be the interface
    // through which next_hop is reachable.
    if (next_hop != 0) { // If it's not a directly connected route (0.0.0.0 next_hop)
        std::optional<IpAddress> if_ip_opt = interface_manager_.get_interface_ip(interface_id);
        std::optional<InterfaceIpConfig> if_ip_config_opt; // Need full config for mask

        auto ip_configs = interface_manager_.get_interface_ip_configs(interface_id);
        if(!ip_configs.empty()){
            if_ip_config_opt = ip_configs[0]; // Using primary IP for this check
        }

        if (if_ip_config_opt.has_value()) {
            IpAddress interface_ip = if_ip_config_opt.value().address;
            IpAddress interface_mask = if_ip_config_opt.value().subnet_mask;
            // Check if next_hop is on the same subnet as the chosen egress interface
            if ((next_hop & interface_mask) != (interface_ip & interface_mask)) {
                // This is a common check to prevent misconfigured routes
                // However, some scenarios might allow this (e.g. point-to-point links with /31 or unnumbered)
                // For now, let's consider it a warning rather than a hard error.
                // Or make it an error if strict checking is desired.
                std::ostringstream error_msg;
                // Simple IP to string for logging (assuming IpAddress is uint32_t network order)
                auto ip_to_str = [](IpAddress ip_val) {
                    std::ostringstream s;
                    s << (ip_val >> 24 & 0xFF) << "." << (ip_val >> 16 & 0xFF) << "." << (ip_val >> 8 & 0xFF) << "." << (ip_val & 0xFF);
                    return s.str();
                };

                error_msg << "Warning/Error: Next-hop " << ip_to_str(ntohl(next_hop))
                          << " may not be reachable on the subnet of interface " << interface_id
                          << " (" << ip_to_str(ntohl(interface_ip)) << "/" << ip_to_str(ntohl(interface_mask)) << ").";
                // For this example, let's return it as an error to be safe.
                return error_msg.str();
            }
        } else if (interface_id != 0) { // If interface_id is specified but has no IP
             std::ostringstream error_msg;
             error_msg << "Error: Egress interface " << interface_id << " has no IP address configured.";
             return error_msg.str();
        }
    }


    routing_manager_.add_static_route(network, mask, next_hop, interface_id, metric);
    // Assuming add_static_route handles internal logic like sorting or duplicate checks.
    // If add_static_route could fail (e.g. table full), it should indicate this.
    // For now, assuming it's void and always "succeeds" from a call perspective.

    return std::nullopt; // Success
}

std::optional<std::string> ManagementService::remove_route(
    const IpAddress& network,
    const IpAddress& mask) {

    // Similar to add_route, one might want to validate that (network & mask) == network.
    // RoutingManager::remove_static_route already does this normalization.

    routing_manager_.remove_static_route(network, mask);
    // remove_static_route in RoutingManager might not indicate if a route was actually found and removed.
    // If feedback on whether a route was actually removed is needed, RoutingManager would need to change.
    // For now, we assume the operation "succeeds" in attempting removal.

    return std::nullopt; // Success (in attempting removal)
}

std::optional<std::string> ManagementService::add_interface_ip(
    uint32_t interface_id,
    const IpAddress& ip_address,
    const IpAddress& subnet_mask) {

    if (!interface_manager_.is_port_valid(interface_id)) {
        std::ostringstream error_msg;
        error_msg << "Error: Interface ID " << interface_id << " is not valid.";
        return error_msg.str();
    }

    // Basic validation for IP and mask (e.g., mask is not zero, IP is not zero)
    // More advanced validation (e.g., IP is not network/broadcast, mask is contiguous)
    // could be added here or assumed to be handled by InterfaceManager or UI.
    if (ip_address == 0) {
        return "Error: IP address cannot be 0.0.0.0.";
    }
    if (subnet_mask == 0) {
        return "Error: Subnet mask cannot be 0.0.0.0.";
    }

    // Check for host bits set in network address part
    // IpAddress calculated_network_addr = ip_address & subnet_mask;
    // if (ip_address != calculated_network_addr && ip_address != (calculated_network_addr | ~subnet_mask) ) {
         // This logic can be complex: needs to check if IP is a valid host IP for the subnet.
         // For example, ensure it's not the network address itself, nor the broadcast address.
         // For simplicity, we'll rely on InterfaceManager or user for this level of detail for now.
    // }


    // Check for existing IP to prevent duplicates on the same interface (InterfaceManager might do this)
    // or on different interfaces if subnets are not allowed to overlap (more complex check).
    std::vector<InterfaceIpConfig> existing_ips = interface_manager_.get_interface_ip_configs(interface_id);
    for (const auto& existing_conf : existing_ips) {
        if (existing_conf.address == ip_address && existing_conf.subnet_mask == subnet_mask) {
            std::ostringstream error_msg;
            error_msg << "Error: IP address " << ip_address << "/" << subnet_mask << " already configured on interface " << interface_id;
            // Ideally, convert IP to string for message. For now, using raw values.
            return error_msg.str();
        }
        // Add check for overlapping subnets if necessary, though that's more complex.
    }

    interface_manager_.add_ip_address(interface_id, ip_address, subnet_mask);
    // Assuming add_ip_address in InterfaceManager handles actual addition.
    // It might also do its own validation.

    return std::nullopt; // Success
}

std::optional<std::string> ManagementService::remove_interface_ip(
    uint32_t interface_id,
    const IpAddress& ip_address,
    const IpAddress& subnet_mask) {

    if (!interface_manager_.is_port_valid(interface_id)) {
        std::ostringstream error_msg;
        error_msg << "Error: Interface ID " << interface_id << " is not valid.";
        return error_msg.str();
    }

    // Check if the IP configuration actually exists before trying to remove
    // InterfaceManager::remove_ip_address might silently do nothing if not found.
    // For more explicit feedback, we can check first.
    bool found = false;
    std::vector<InterfaceIpConfig> existing_ips = interface_manager_.get_interface_ip_configs(interface_id);
    for (const auto& existing_conf : existing_ips) {
        if (existing_conf.address == ip_address && existing_conf.subnet_mask == subnet_mask) {
            found = true;
            break;
        }
    }

    if (!found) {
        std::ostringstream error_msg;
        error_msg << "Error: IP address " << ip_address << "/" << subnet_mask << " not found on interface " << interface_id;
        // Ideally, convert IP to string.
        return error_msg.str();
    }

    interface_manager_.remove_ip_address(interface_id, ip_address, subnet_mask);
    // Assuming remove_ip_address in InterfaceManager handles actual removal.

    return std::nullopt; // Success
}

} // namespace netflow
