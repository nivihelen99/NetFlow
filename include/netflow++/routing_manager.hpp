#ifndef NETFLOW_ROUTING_MANAGER_HPP
#define NETFLOW_ROUTING_MANAGER_HPP

#include "netflow++/packet.hpp" // For IpAddress and ip_mask_to_prefix_length
#include <vector>               // For std::vector
#include <optional>             // For std::optional
#include <mutex>                // For std::mutex
#include <cstdint>              // For uint32_t, uint8_t
#include <algorithm>            // For std::remove_if, std::sort (used in .cpp)

namespace netflow {

enum class RouteSource {
    STATIC,
    CONNECTED,
    ISIS_L1,
    ISIS_L2
};

struct RouteEntry {
    IpAddress destination_network;
    IpAddress subnet_mask;
    IpAddress next_hop_ip;
    uint32_t egress_interface_id;
    int metric;
    RouteSource source;
    uint8_t administrative_distance;

    RouteEntry(IpAddress net, IpAddress mask, IpAddress next_hop, uint32_t if_id, int m, RouteSource src, uint8_t ad)
        : destination_network(net), subnet_mask(mask), next_hop_ip(next_hop),
          egress_interface_id(if_id), metric(m), source(src), administrative_distance(ad) {}

    RouteEntry() : destination_network(0), subnet_mask(0), next_hop_ip(0),
                   egress_interface_id(0), metric(0), source(RouteSource::STATIC), administrative_distance(255) {}

    bool operator<(const RouteEntry& other) const {
        uint8_t this_prefix_len = ip_mask_to_prefix_length(this->subnet_mask);
        uint8_t other_prefix_len = ip_mask_to_prefix_length(other.subnet_mask);

        if (this_prefix_len != other_prefix_len) {
            return this_prefix_len > other_prefix_len;
        }
        if (administrative_distance != other.administrative_distance) {
            return administrative_distance < other.administrative_distance;
        }
        if (metric != other.metric) {
            return metric < other.metric;
        }
        if (destination_network != other.destination_network) {
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
    RoutingManager();

    void add_static_route(const IpAddress& destination_network, const IpAddress& subnet_mask,
                          const IpAddress& next_hop_ip, uint32_t egress_interface_id,
                          int metric = 1, uint8_t admin_distance = 1);

    void add_connected_route(const IpAddress& network_address,
                             const IpAddress& subnet_mask,
                             uint32_t interface_id);

    void remove_static_route(const IpAddress& destination_network, const IpAddress& subnet_mask);

    void update_dynamic_routes(const std::vector<RouteEntry>& new_routes, RouteSource source_type);

    std::optional<RouteEntry> lookup_route(const IpAddress& destination_ip) const;

    std::vector<RouteEntry> get_routing_table() const;

private:
    std::vector<RouteEntry> routing_table_;
    mutable std::mutex table_mutex_;

    void rebuild_routing_table(); // Implementation would use std::sort, std::remove_if
};

} // namespace netflow

#endif // NETFLOW_ROUTING_MANAGER_HPP
