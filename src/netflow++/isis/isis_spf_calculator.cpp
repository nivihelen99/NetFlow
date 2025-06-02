#include "netflow++/isis/isis_spf_calculator.hpp"
#include "netflow++/isis/isis_pdu_constants.hpp" // For TLV type constants
#include "netflow++/byte_swap.hpp"             // For ntohl, ntohs

#include <iostream> // For debugging

namespace netflow {
namespace isis {

// Custom comparator for priority queue (SpfNodePathInfo)
struct SpfNodePathInfoComparator {
    bool operator()(const SpfNodePathInfo& a, const SpfNodePathInfo& b) const {
        return a.total_metric > b.total_metric; // Min-heap based on total_metric
    }
};


IsisSpfCalculator::IsisSpfCalculator(const SystemID& local_sys_id, IsisLevel level, const IsisLsdb* lsdb)
    : local_system_id_(local_sys_id), level_(level), lsdb_(lsdb) {
    if (!lsdb_) {
        throw std::invalid_argument("IsisSpfCalculator: LSDB pointer cannot be null.");
    }
}

IpAddress IsisSpfCalculator::calculate_subnet_mask(uint8_t prefix_len) const {
    if (prefix_len > 32) prefix_len = 32;
    uint32_t mask = 0;
    if (prefix_len > 0) {
        mask = (0xFFFFFFFF << (32 - prefix_len));
    }
    return IpAddress(htonl(mask)); // IpAddress constructor expects host order usually, but mask is often network
                                   // Let's assume IpAddress handles this, or stores as uint32_t and handles conversion.
                                   // For consistency, IpAddress should store in host order. Mask construction correct.
}

// Placeholder - In a real scenario, this would query IsisInterfaceManager or use pre-computed adjacency data.
// For SPF based purely on LSDB, we'd find the neighbor's LSP and get its IP Interface addresses.
// The local egress interface is the one where this neighbor adjacency exists.
std::vector<IsisSpfCalculator::DirectNeighborInfo> IsisSpfCalculator::get_direct_neighbor_info(const SystemID& neighbor_id) const {
    // This is a simplified stub.
    // A real implementation would:
    // 1. Check IsisInterfaceManager for an active adjacency to neighbor_id.
    // 2. Get the interface_id for that adjacency.
    // 3. Get the neighbor's reported IP address from the Hello (stored in IsisAdjacency).
    // For now, return empty. This means first hop IP/interface determination will be tricky.
    // The SPF algorithm below will try to populate first_hop_router_ips and local_egress_interface_ids
    // when relaxing edges from the local_system_id_.
    return {};
}


void IsisSpfCalculator::parse_lsp_links(const LinkStatePdu& lsp,
                                      std::map<SystemID, uint32_t>& out_neighbors,
                                      std::vector<IpReachabilityInfo>& out_ip_prefixes) const {
    out_neighbors.clear();
    out_ip_prefixes.clear();

    for (const auto& tlv : lsp.tlvs) {
        // IS Reachability (Type 2 for L1/L2, or 22 for Extended IS for L2)
        if (tlv.type == IS_REACHABILITY_TLV_TYPE || tlv.type == EXTENDED_IS_REACHABILITY_TLV_TYPE) {
            BufferReader reader(tlv.value);
            while (reader.offset < reader.size) {
                // Type 2: Metric (1) + Reserved (1) + SystemID (6) + Reserved (1) ...
                // Type 22: Metric (3) + SystemID (7: SysID+Pseudonode) + SubTLVs
                // This parsing needs to be accurate based on TLV type.
                // Simplified parsing for Type 2 concept:
                if (tlv.type == IS_REACHABILITY_TLV_TYPE && reader.can_read(8)) { // 1 metric + 1 res + 6 sysid
                    uint8_t metric_val;
                    parse_u8(reader, metric_val); // Metric
                    reader.advance(1); // Skip reserved byte

                    SystemID neighbor_sys_id;
                    parse_system_id(reader, neighbor_sys_id);
                    
                    if (out_neighbors.find(neighbor_sys_id) == out_neighbors.end() || metric_val < out_neighbors[neighbor_sys_id]) {
                        out_neighbors[neighbor_sys_id] = metric_val;
                    }
                } else if (tlv.type == EXTENDED_IS_REACHABILITY_TLV_TYPE && reader.can_read(10)) { // 3 metric + 7 sysid_pn
                     uint32_t metric_val = 0;
                     // Read 3 bytes for metric (e.g. into uint32_t)
                     uint8_t m_bytes[3];
                     parse_bytes(reader, m_bytes, 3);
                     metric_val = (static_cast<uint32_t>(m_bytes[0]) << 16) | 
                                  (static_cast<uint32_t>(m_bytes[1]) << 8)  | 
                                  (static_cast<uint32_t>(m_bytes[2]));

                    SystemID neighbor_sys_id; // 6 bytes
                    std::array<uint8_t, 7> neighbor_lan_id; // 7 bytes (SysID + PN)
                    parse_bytes(reader, neighbor_lan_id.data(), 7);
                    std::copy(neighbor_lan_id.begin(), neighbor_lan_id.begin() + 6, neighbor_sys_id.begin());
                    // We are interested in paths to other routers (SystemIDs), not pseudonodes here directly.
                    // If neighbor_lan_id[6] != 0, it's a pseudonode. We connect to the router part.

                    if (out_neighbors.find(neighbor_sys_id) == out_neighbors.end() || metric_val < out_neighbors[neighbor_sys_id]) {
                        out_neighbors[neighbor_sys_id] = metric_val;
                    }
                    // Skip any sub-TLVs for now
                    // The length of sub-TLVs would need to be parsed to advance reader correctly.
                    // For now, assume no sub-TLVs or fixed entry size. This is a simplification.
                    // A robust parser would look at tlv.length and the parsed fields.
                    // For now, assume entries are packed and we just read fixed parts.
                } else {
                    break; // Cannot read entry, malformed or unknown variant
                }
            }
        }
        // IP Reachability (Type 128 for Internal, 130 for External - deprecated, 135 for Extended IP)
        else if (tlv.type == IP_INTERNAL_REACH_TLV_TYPE || tlv.type == EXTENDED_IP_REACHABILITY_TLV_TYPE) {
            // This parsing was sketched in isis_pdu.cpp, should be robust there.
            // For now, a simplified conceptual parsing.
            ExtendedIpReachabilityTlvValue val_struct;
            if (parse_extended_ip_reachability_tlv_value(tlv.value, val_struct)) { // Assumes this function exists and works
                out_ip_prefixes.insert(out_ip_prefixes.end(), val_struct.reachabilityEntries.begin(), val_struct.reachabilityEntries.end());
            }
        }
    }
}


std::vector<SpfRouteEntry> IsisSpfCalculator::calculate_spf() const {
    if (!lsdb_) return {};

    std::map<SystemID, SpfNodePathInfo> spf_tree;
    std::priority_queue<SpfNodePathInfo, std::vector<SpfNodePathInfo>, SpfNodePathInfoComparator> pq;
    
    // Initialize SPF for the local system
    SpfNodePathInfo& local_node_info = spf_tree[local_system_id_];
    local_node_info.node_id = local_system_id_;
    local_node_info.total_metric = 0;
    pq.push(local_node_info);

    std::vector<SpfRouteEntry> routes;

    while (!pq.empty()) {
        SpfNodePathInfo current_path_info = pq.top();
        pq.pop();

        const SystemID& current_node_id = current_path_info.node_id;

        // If already processed with a shorter or equal path (due to priority queue behavior with multiple entries for same node)
        if (current_path_info.total_metric > spf_tree[current_node_id].total_metric) {
            continue; 
        }
        // If already finalized (this check is more robust with a separate 'visited' set)
        // For now, rely on the metric comparison above. A 'visited' set is better.
        // Let's add a visited set for clarity and correctness with ECMP.
        // std::set<SystemID> visited_nodes; -- should be outside loop or part of SpfNodePathInfo.
        // For now, the check `current_path_info.total_metric > spf_tree[current_node_id].total_metric` handles cases
        // where a stale, longer path is popped. If it's equal, we process for ECMP.

        // Fetch LSP for current_node_id
        // Assuming LSP ID for a router is SystemID + 0 (pseudonode/lsp-number 0)
        LspId current_lsp_id = {current_node_id, 0};
        std::optional<LinkStatePdu> lsp_opt = lsdb_->get_lsp(current_lsp_id);

        if (!lsp_opt || ntohs(lsp_opt->remainingLifetime) == 0) {
            continue; // LSP not found or purged
        }
        const LinkStatePdu& current_lsp = lsp_opt.value();

        // Parse neighbors and advertised IP prefixes from this LSP
        std::map<SystemID, uint32_t> neighbors_of_current; // Neighbor SystemID -> metric
        std::vector<IpReachabilityInfo> advertised_prefixes_of_current;
        parse_lsp_links(current_lsp, neighbors_of_current, advertised_prefixes_of_current);

        // Add routes for prefixes advertised by current_node_id
        for (const auto& prefix_info : advertised_prefixes_of_current) {
            SpfRouteEntry route;
            route.destination_prefix = IpAddress(prefix_info.ipAddress); // Assumes ipAddress is network prefix
            route.subnet_mask = calculate_subnet_mask(static_cast<uint8_t>(prefix_info.subnetMask)); // subnetMask here is prefix_len
            route.metric = current_path_info.total_metric + prefix_info.metric;
            route.advertising_router_id = current_node_id;
            
            if (current_node_id == local_system_id_) { // Prefix advertised by self (directly connected)
                route.metric = prefix_info.metric; // Usually 0 or small for connected
                // For connected routes, next_hop is self, egress_interface needs to be found.
                // This requires knowing which local interface hosts this prefix.
                // For now, leave next_hop_ips and egress_interface_ids empty or mark as 'directly connected'.
                route.next_hop_ips.insert(IpAddress("0.0.0.0")); // Special marker for connected
            } else {
                route.next_hop_ips = current_path_info.first_hop_router_ips;
                route.egress_interface_ids = current_path_info.local_egress_interface_ids;
            }
            routes.push_back(route);
        }

        // Relax edges to neighbors
        for (const auto& neighbor_pair : neighbors_of_current) {
            const SystemID& adj_node_id = neighbor_pair.first;
            uint32_t link_metric = neighbor_pair.second;
            uint32_t new_metric_to_adj_node = current_path_info.total_metric + link_metric;

            // Ensure adj_node_id entry exists in spf_tree for safe access
            if (spf_tree.find(adj_node_id) == spf_tree.end()) {
                 spf_tree[adj_node_id].node_id = adj_node_id; // Initialize if new
            }

            if (new_metric_to_adj_node < spf_tree[adj_node_id].total_metric) {
                spf_tree[adj_node_id].total_metric = new_metric_to_adj_node;
                spf_tree[adj_node_id].predecessors = {current_node_id}; // New shortest path

                if (current_node_id == local_system_id_) { // adj_node_id is a direct neighbor
                    // Need to get IP of adj_node_id and interface to it.
                    // This is where get_direct_neighbor_info would be useful.
                    // For now, this part is tricky without IsisInterfaceManager access.
                    // Assume adj_node_id's LSP has an IP Interface TLV that we can use as its "router ID IP"
                    // And the interface_id is the one this adjacency is on (from our perspective).
                    // This is a simplification.
                    spf_tree[adj_node_id].first_hop_router_ips.clear(); // Will be filled if we can find its IP
                    spf_tree[adj_node_id].local_egress_interface_ids.clear(); // Will be filled if we know interface

                    // Try to find adj_node_id's IP from its LSP (if available)
                    LspId adj_lsp_id = {adj_node_id, 0};
                    auto adj_lsp_opt = lsdb_->get_lsp(adj_lsp_id);
                    if (adj_lsp_opt) {
                        for (const auto& tlv : adj_lsp_opt->tlvs) {
                            if (tlv.type == IP_INTERFACE_ADDRESS_TLV_TYPE && !tlv.value.empty()) {
                                uint32_t adj_ip_val_net;
                                std::memcpy(&adj_ip_val_net, tlv.value.data(), sizeof(uint32_t));
                                spf_tree[adj_node_id].first_hop_router_ips.insert(IpAddress(ntohl(adj_ip_val_net)));
                                break; // Take first one
                            }
                        }
                    }
                    // Finding local_egress_interface_id requires InterfaceManager knowledge about the adjacency.
                    // This is a limitation of pure LSDB SPF.

                } else { // Path to adj_node_id is via current_node_id
                    spf_tree[adj_node_id].first_hop_router_ips = spf_tree[current_node_id].first_hop_router_ips;
                    spf_tree[adj_node_id].local_egress_interface_ids = spf_tree[current_node_id].local_egress_interface_ids;
                }
                pq.push(spf_tree[adj_node_id]);

            } else if (new_metric_to_adj_node == spf_tree[adj_node_id].total_metric) { // ECMP
                spf_tree[adj_node_id].predecessors.insert(current_node_id);
                if (current_node_id == local_system_id_) {
                    // Add another direct path for ECMP
                    // Similar logic as above to find direct neighbor IP/interface
                } else {
                    spf_tree[adj_node_id].first_hop_router_ips.insert(
                        spf_tree[current_node_id].first_hop_router_ips.begin(),
                        spf_tree[current_node_id].first_hop_router_ips.end());
                    spf_tree[adj_node_id].local_egress_interface_ids.insert(
                        spf_tree[current_node_id].local_egress_interface_ids.begin(),
                        spf_tree[current_node_id].local_egress_interface_ids.end());
                }
                // No need to re-push to PQ if already visited or path is not strictly shorter.
                // However, some Dijkstra variants re-add for ECMP processing if structure changes.
                // For simplicity, only add if path strictly shorter. ECMP data (predecessors, first_hops) is updated.
            }
        }
    }

    // Post-process routes: remove duplicates, select best if multiple ads for same prefix
    // For now, this is basic. A real routing table would handle this more robustly.
    std::sort(routes.begin(), routes.end());
    routes.erase(std::unique(routes.begin(), routes.end()), routes.end());
    
    // Filter routes to ensure only best metric for each prefix
    std::map<std::pair<IpAddress, IpAddress>, SpfRouteEntry> best_routes_map;
    for(const auto& r : routes) {
        auto key = std::make_pair(r.destination_prefix, r.subnet_mask);
        if (best_routes_map.find(key) == best_routes_map.end() || r.metric < best_routes_map[key].metric) {
            best_routes_map[key] = r;
        } else if (r.metric == best_routes_map[key].metric) {
            // ECMP: merge next hops and interfaces if metrics are equal
            best_routes_map[key].next_hop_ips.insert(r.next_hop_ips.begin(), r.next_hop_ips.end());
            best_routes_map[key].egress_interface_ids.insert(r.egress_interface_ids.begin(), r.egress_interface_ids.end());
        }
    }
    routes.clear();
    for(const auto& pair : best_routes_map) {
        // Filter out 0.0.0.0 next hops if other valid ones exist for ECMP
        if (pair.second.next_hop_ips.size() > 1) {
            auto it = pair.second.next_hop_ips.find(IpAddress("0.0.0.0"));
            if (it != pair.second.next_hop_ips.end()) {
                 // If it's not the only next_hop, remove it. If it is the only one, it's a connected route.
                if (pair.second.next_hop_ips.size() > 1) { // Check again after potential erase
                    // This logic is tricky. If 0.0.0.0 is present with others, it's ambiguous.
                    // For now, if any non-0.0.0.0 exists, prefer that.
                }
            }
        }
        routes.push_back(pair.second);
    }


    return routes;
}


} // namespace isis
} // namespace netflow

// Constants for TLV parsing (should be in a common header like isis_pdu_constants.hpp or isis_common.hpp)
#ifndef IS_REACHABILITY_TLV_TYPE
#define IS_REACHABILITY_TLV_TYPE 2
#endif
#ifndef EXTENDED_IS_REACHABILITY_TLV_TYPE
#define EXTENDED_IS_REACHABILITY_TLV_TYPE 22
#endif
#ifndef IP_INTERNAL_REACH_TLV_TYPE
#define IP_INTERNAL_REACH_TLV_TYPE 128
#endif
#ifndef EXTENDED_IP_REACHABILITY_TLV_TYPE
#define EXTENDED_IP_REACHABILITY_TLV_TYPE 135
#endif
#ifndef IP_INTERFACE_ADDRESS_TLV_TYPE
#define IP_INTERFACE_ADDRESS_TLV_TYPE 132
#endif

// Assumed parsing functions (from isis_pdu.cpp or similar)
// parse_extended_ip_reachability_tlv_value(tlv.value, val_struct)
// parse_u8, parse_system_id, parse_bytes from isis_pdu.cpp's BufferReader context.
// These might need to be exposed or reimplemented if isis_pdu.cpp's BufferReader is not accessible/suitable.
// For this file, they are used conceptually.
```
