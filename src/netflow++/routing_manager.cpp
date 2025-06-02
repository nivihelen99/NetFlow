#include "netflow++/routing_manager.hpp"
#include <algorithm> // For std::sort, std::remove_if
#include <vector>    // Included by routing_manager.hpp but good practice for .cpp if used directly
#if __has_include(<arpa/inet.h>) // For ntohl
#include <arpa/inet.h>
#elif __has_include(<winsock2.h>)
#include <winsock2.h>
#endif
#include <iostream> // For potential debug logging


namespace netflow {

RoutingManager::RoutingManager() {
    // Constructor body can be empty for now.
}

void RoutingManager::add_static_route(const IpAddress& destination_network, const IpAddress& subnet_mask,
                                      const IpAddress& next_hop_ip, uint32_t egress_interface_id, 
                                      int metric, uint8_t admin_distance) {
    std::lock_guard<std::mutex> lock(table_mutex_);

    IpAddress actual_network_address = destination_network & subnet_mask;

    // Remove existing static route to the same exact prefix to prevent duplicates if re-adding with new params
    routing_table_.erase(
        std::remove_if(routing_table_.begin(), routing_table_.end(),
                       [&](const RouteEntry& entry) {
                           return entry.source == RouteSource::STATIC &&
                                  entry.destination_network == actual_network_address &&
                                  entry.subnet_mask == subnet_mask;
                       }),
        routing_table_.end());
    
    routing_table_.emplace_back(actual_network_address, subnet_mask, next_hop_ip, 
                                egress_interface_id, metric, RouteSource::STATIC, admin_distance);
    rebuild_routing_table();
}

void RoutingManager::add_connected_route(const IpAddress& network_address,
                                         const IpAddress& subnet_mask,
                                         uint32_t interface_id) {
    std::lock_guard<std::mutex> lock(table_mutex_);
    // Connected routes: AD 0, Metric 0. Next hop is 0.0.0.0.
    routing_table_.emplace_back(network_address & subnet_mask, subnet_mask, IpAddress(0),
                                interface_id, 0, RouteSource::CONNECTED, 0);
    rebuild_routing_table();
}

void RoutingManager::remove_static_route(const IpAddress& destination_network, const IpAddress& subnet_mask) {
    std::lock_guard<std::mutex> lock(table_mutex_);
    IpAddress actual_network_address = destination_network & subnet_mask;
    routing_table_.erase(
        std::remove_if(routing_table_.begin(), routing_table_.end(),
                       [&](const RouteEntry& entry) {
                           return entry.source == RouteSource::STATIC && // Important: only remove static
                                  entry.destination_network == actual_network_address &&
                                  entry.subnet_mask == subnet_mask;
                       }),
        routing_table_.end());
    // No need to rebuild_routing_table() if only removing, unless order is critical for other operations
    // or to remove gaps, but vector erase handles gaps. Sorting is for lookup optimization.
    // Let's call it to be safe and maintain a canonical state.
    rebuild_routing_table(); 
}

void RoutingManager::update_dynamic_routes(const std::vector<RouteEntry>& new_routes, RouteSource source_type) {
    std::lock_guard<std::mutex> lock(table_mutex_);
    // Remove all existing routes from the specified dynamic source
    routing_table_.erase(
        std::remove_if(routing_table_.begin(), routing_table_.end(),
                       [&](const RouteEntry& entry) {
                           return entry.source == source_type;
                       }),
        routing_table_.end());

    // Add all new routes. Their source and AD should be correctly set by the caller (e.g. IsisManager)
    routing_table_.insert(routing_table_.end(), new_routes.begin(), new_routes.end());
    
    rebuild_routing_table();
}

std::optional<RouteEntry> RoutingManager::lookup_route(const IpAddress& destination_ip) const {
    std::lock_guard<std::mutex> lock(table_mutex_); 

    // The routing_table_ is sorted by rebuild_routing_table() according to:
    // 1. Longest prefix match (descending prefix length)
    // 2. Lowest administrative distance
    // 3. Lowest metric
    // So, the first entry that matches the prefix criteria is the best route.
    for (const auto& entry : routing_table_) {
        if ((destination_ip & entry.subnet_mask) == entry.destination_network) {
            return entry; // Return a copy of the first (and thus best) matched entry
        }
    }
    return std::nullopt; // No route found
}

std::vector<RouteEntry> RoutingManager::get_routing_table() const {
    std::lock_guard<std::mutex> lock(table_mutex_);
    return routing_table_; // Return a copy of the table
}

void RoutingManager::rebuild_routing_table() {
    // Sorts the table based on RouteEntry::operator<
    // Order: Longest prefix, then lowest AD, then lowest metric.
    std::sort(routing_table_.begin(), routing_table_.end());

    // Optional: remove dominated routes if not handled by specific logic.
    // E.g., if we have 10.0.0.0/8 AD 10 and 10.0.0.0/8 AD 100 from different sources,
    // the AD 100 one will never be used if lookup_route just picks the first one after sorting.
    // The current lookup_route correctly handles this by iterating and checking AD.
    // The sort order itself ensures that the first match found by lookup_route's iteration
    // will be the best one according to longest prefix, then AD, then metric.
}

} // namespace netflow
