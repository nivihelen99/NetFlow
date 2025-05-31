#include "netflow++/routing_manager.hpp"
#include <algorithm> // For std::sort, std::remove_if
#include <vector>    // Included by routing_manager.hpp but good practice for .cpp if used directly
#if __has_include(<arpa/inet.h>) // For ntohl
#include <arpa/inet.h>
#elif __has_include(<winsock2.h>)
#include <winsock2.h>
#endif

namespace netflow {

RoutingManager::RoutingManager() {
    // Constructor body can be empty for now.
    // The routing_table_ (std::vector) and table_mutex_ (std::mutex)
    // will be default-initialized.
}

void RoutingManager::add_static_route(const IpAddress& destination_network, const IpAddress& subnet_mask,
                                      const IpAddress& next_hop_ip, uint32_t egress_interface_id, int metric) {
    std::lock_guard<std::mutex> lock(table_mutex_);

    // Ensure the provided destination_network is actually a network address
    IpAddress actual_network_address = destination_network & subnet_mask;

    // Optional: Check for duplicates
    for (const auto& entry : routing_table_) {
        if (entry.destination_network == actual_network_address &&
            entry.subnet_mask == subnet_mask &&
            entry.next_hop_ip == next_hop_ip && // Could be more nuanced if just updating metric/interface
            entry.egress_interface_id == egress_interface_id) {
            // Route exists, perhaps update metric or just return
            // For this implementation, we'll assume updates are handled by remove then add, or we simply don't add duplicates.
            // To prevent exact duplicates (all fields same):
            // if (entry.metric == metric) return; // if all same, do nothing
            return; // Simple: don't add if a very similar route (network, mask, next_hop, iface) exists.
        }
    }

    routing_table_.emplace_back(actual_network_address, subnet_mask, next_hop_ip, egress_interface_id, metric);

    // Sort the routing table: longest prefix match first (most bits in subnet mask)
    // then by metric, then by destination network for stable ordering.
    std::sort(routing_table_.begin(), routing_table_.end(),
        [](const RouteEntry& a, const RouteEntry& b) {
            // __builtin_popcount works on integers. IpAddress is uint32_t.
            // Masks are already in network byte order, ntohl converts to host byte order for popcount.
            uint32_t popcount_a = __builtin_popcount(ntohl(a.subnet_mask));
            uint32_t popcount_b = __builtin_popcount(ntohl(b.subnet_mask));

            if (popcount_a != popcount_b) {
                return popcount_a > popcount_b; // Higher popcount (longer mask) first
            }
            // If subnet mask lengths are equal, sort by metric (lower is better)
            if (a.metric != b.metric) {
                return a.metric < b.metric;
            }
            // If metrics are also equal, sort by destination network for stability
            // (ntohl for consistent comparison if IPs are stored network order)
            return ntohl(a.destination_network) < ntohl(b.destination_network);
        });
}

void RoutingManager::remove_static_route(const IpAddress& destination_network, const IpAddress& subnet_mask) {
    std::lock_guard<std::mutex> lock(table_mutex_);

    IpAddress actual_network_address = destination_network & subnet_mask;

    routing_table_.erase(
        std::remove_if(routing_table_.begin(), routing_table_.end(),
                       [&](const RouteEntry& entry) {
                           return entry.destination_network == actual_network_address &&
                                  entry.subnet_mask == subnet_mask;
                           // This removes all routes for that network/mask.
                           // If multiple routes to the same network (e.g. different next hops/metrics)
                           // were allowed and needed specific removal, the criteria would need more fields.
                       }),
        routing_table_.end());
}

std::optional<RouteEntry> RoutingManager::lookup_route(const IpAddress& destination_ip) const {
    std::lock_guard<std::mutex> lock(table_mutex_); // Mutex is mutable

    for (const auto& entry : routing_table_) {
        // Apply mask to the destination IP and compare with the route's network address
        // Both entry.destination_network and entry.subnet_mask are in network byte order.
        // destination_ip is also assumed to be in network byte order.
        if ((destination_ip & entry.subnet_mask) == entry.destination_network) {
            return entry; // Return a copy of the matched entry
        }
    }
    return std::nullopt; // No route found
}

std::vector<RouteEntry> RoutingManager::get_routing_table() const {
    std::lock_guard<std::mutex> lock(table_mutex_);
    return routing_table_; // Return a copy of the table
}

} // namespace netflow
