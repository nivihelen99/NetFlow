#ifndef NETFLOW_ROUTING_MANAGER_HPP
#define NETFLOW_ROUTING_MANAGER_HPP

#include "netflow++/packet.hpp" // For IpAddress
#include <vector>
#include <optional>
#include <mutex>
#include <cstdint> // For uint32_t
#include <algorithm> // For std::remove_if, std::sort

namespace netflow {

enum class RouteSource {
    STATIC,
    CONNECTED, // For directly connected networks
    ISIS_L1,
    ISIS_L2
    // Other dynamic protocols can be added here
};

// Represents an entry in the routing table
struct RouteEntry {
    IpAddress destination_network;  // Network address (e.g., 192.168.1.0)
    IpAddress subnet_mask;          // Subnet mask (e.g., 255.255.255.0)
    IpAddress next_hop_ip;          // IP address of the next hop router. 0 if directly connected.
    uint32_t egress_interface_id;   // The interface ID to send the packet out on.
    int metric;                     // Cost of this route, e.g., hop count or administrative cost.
    RouteSource source;
    uint8_t administrative_distance;

    // Constructor for convenience
    RouteEntry(IpAddress net, IpAddress mask, IpAddress next_hop, uint32_t if_id, int m, RouteSource src, uint8_t ad)
        : destination_network(net), subnet_mask(mask), next_hop_ip(next_hop),
          egress_interface_id(if_id), metric(m), source(src), administrative_distance(ad) {}

    // Default constructor
    RouteEntry() : destination_network(0), subnet_mask(0), next_hop_ip(0), 
                   egress_interface_id(0), metric(0), source(RouteSource::STATIC), administrative_distance(255) {}

    // For sorting, primarily by prefix length (descending), then AD, then metric
    bool operator<(const RouteEntry& other) const {
        uint32_t this_prefix_len = subnet_mask.to_prefix_length(); // Assuming IpAddress has this
        uint32_t other_prefix_len = other.subnet_mask.to_prefix_length();

        if (this_prefix_len != other_prefix_len) {
            return this_prefix_len > other_prefix_len; // Longer prefix is better (comes first in sort if using std::sort)
        }
        if (administrative_distance != other.administrative_distance) {
            return administrative_distance < other.administrative_distance;
        }
        if (metric != other.metric) {
            return metric < other.metric;
        }
        // Further tie-breaking if necessary
        if (destination_network != other.destination_network) { // Ensure consistent ordering
            return destination_network < other.destination_network;
        }
        if (next_hop_ip != other.next_hop_ip) {
             return next_hop_ip < other.next_hop_ip;
        }
        return egress_interface_id < other.egress_interface_id;
    }
     bool operator==(const RouteEntry& other) const {
        return destination_network == other.destination_network &&
               subnet_mask == other.subnet_mask &&
               next_hop_ip == other.next_hop_ip &&
               egress_interface_id == other.egress_interface_id &&
               metric == other.metric &&
               source == other.source &&
               administrative_distance == other.administrative_distance;
    }
};

class RoutingManager {
public:
    RoutingManager(); // Constructor

    // Methods for managing and querying routes
    void add_static_route(const IpAddress& destination_network, const IpAddress& subnet_mask,
                          const IpAddress& next_hop_ip, uint32_t egress_interface_id, 
                          int metric = 1, uint8_t admin_distance = 1); // Default AD for static
    
    void add_connected_route(const IpAddress& network_address,
                             const IpAddress& subnet_mask,
                             uint32_t interface_id);

    void remove_static_route(const IpAddress& destination_network, const IpAddress& subnet_mask); // May need more params to be unique
    
    // Method for dynamic protocols to update their routes
    void update_dynamic_routes(const std::vector<RouteEntry>& new_routes, RouteSource source_type);

    std::optional<RouteEntry> lookup_route(const IpAddress& destination_ip) const;

    // Method to get a copy of the routing table (e.g., for display or debugging)
    std::vector<RouteEntry> get_routing_table() const;

private:
    std::vector<RouteEntry> routing_table_;
    mutable std::mutex table_mutex_; // mutable to allow locking in const lookup_route

    // Helper to sort and prune routes (e.g. after updates)
    void rebuild_routing_table();
};

} // namespace netflow

#endif // NETFLOW_ROUTING_MANAGER_HPP
