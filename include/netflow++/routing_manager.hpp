#ifndef NETFLOW_ROUTING_MANAGER_HPP
#define NETFLOW_ROUTING_MANAGER_HPP

#include "netflow++/packet.hpp" // For IpAddress
#include <vector>
#include <optional>
#include <mutex>
#include <cstdint> // For uint32_t

namespace netflow {

// Represents an entry in the routing table
struct RouteEntry {
    IpAddress destination_network;  // Network address (e.g., 192.168.1.0)
    IpAddress subnet_mask;          // Subnet mask (e.g., 255.255.255.0)
    IpAddress next_hop_ip;          // IP address of the next hop router. 0 if directly connected.
    uint32_t egress_interface_id;   // The interface ID to send the packet out on.
    int metric;                     // Cost of this route, e.g., hop count or administrative cost.

    // Constructor for convenience
    RouteEntry(IpAddress net, IpAddress mask, IpAddress next_hop, uint32_t if_id, int m = 1)
        : destination_network(net), subnet_mask(mask), next_hop_ip(next_hop),
          egress_interface_id(if_id), metric(m) {}

    // Default constructor (useful for vector initialization or default states)
    RouteEntry() : destination_network(0), subnet_mask(0), next_hop_ip(0), egress_interface_id(0), metric(0) {}
};

class RoutingManager {
public:
    RoutingManager(); // Constructor

    // Methods for managing and querying routes
    void add_static_route(const IpAddress& destination_network, const IpAddress& subnet_mask,
                          const IpAddress& next_hop_ip, uint32_t egress_interface_id, int metric = 1);
    void remove_static_route(const IpAddress& destination_network, const IpAddress& subnet_mask);
    std::optional<RouteEntry> lookup_route(const IpAddress& destination_ip) const;

    // Method to get a copy of the routing table (e.g., for display or debugging)
    std::vector<RouteEntry> get_routing_table() const;

private:
    std::vector<RouteEntry> routing_table_;
    mutable std::mutex table_mutex_; // mutable to allow locking in const lookup_route
};

} // namespace netflow

#endif // NETFLOW_ROUTING_MANAGER_HPP
