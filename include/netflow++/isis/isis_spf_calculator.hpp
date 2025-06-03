#ifndef NETFLOW_ISIS_SPF_CALCULATOR_HPP
#define NETFLOW_ISIS_SPF_CALCULATOR_HPP

#include "netflow++/isis/isis_common.hpp"
#include "netflow++/isis/isis_pdu.hpp" // For TLV structures
#include "netflow++/isis/isis_lsdb.hpp" // To access LSPs
#include "netflow++/packet.hpp"      // For IpAddress
// Assuming routing_manager.hpp defines RouteEntry, or we define a local equivalent.
// For now, let's define a local structure for clarity, can be mapped to RouteEntry later.

#include <cstdint>
#include <vector>
#include <map>
#include <set>
#include <optional>
#include <algorithm>
#include <limits>
#include <queue> // For priority_queue

namespace netflow {
namespace isis {

// Structure for Multicast Forwarding Entries
// Moved before IsisSpfCalculator to resolve declaration order issues
struct MulticastRouteEntry {
    IpAddress source_address{};       // Source of the multicast stream (0.0.0.0 for shared tree root / any source)
    IpAddress group_address{};        // Multicast group address
    uint32_t upstream_interface_id = 0; // Incoming interface (RPF interface towards source)
                                      // 0 if this router is the source or RPF cannot be determined.
    std::set<uint32_t> downstream_interface_ids{}; // Outgoing interfaces for this (S,G) or (*,G)
    IsisLevel level = IsisLevel::NONE; // IS-IS level this route was derived from
    uint32_t metric_to_source = 0; // Optional: metric to the source S or Root for (*,G)

    bool operator==(const MulticastRouteEntry& other) const {
        return source_address == other.source_address &&
               group_address == other.group_address &&
               upstream_interface_id == other.upstream_interface_id &&
               downstream_interface_ids == other.downstream_interface_ids &&
               level == other.level;
    }

    // Basic less-than for sorting/set storage
    bool operator<(const MulticastRouteEntry& other) const {
        if (source_address < other.source_address) return true;
        if (source_address > other.source_address) return false;
        if (group_address < other.group_address) return true;
        if (group_address > other.group_address) return false;
        if (upstream_interface_id < other.upstream_interface_id) return true;
        if (upstream_interface_id > other.upstream_interface_id) return false;
        return downstream_interface_ids < other.downstream_interface_ids;
    }
};

// Structure to hold SPF calculation results for each reachable IP prefix.
// This can be adapted to/from a common RouteEntry structure later.
struct SpfRouteEntry {
    IpAddress destination_prefix{};
    IpAddress subnet_mask{}; // Mask for the destination_prefix
    uint32_t metric = 0;
    std::set<IpAddress> next_hop_ips{}; // Can be multiple for ECMP
    std::set<uint32_t> egress_interface_ids{}; // Local interface IDs to reach the next hop(s)
    SystemID advertising_router_id{}; // SystemID of the router that advertised this prefix
    bool is_inter_area = false; // TODO: Populate if L1/L2 routing is implemented

    // Equality and less-than operators for sorting or storing in sets if needed
    bool operator==(const SpfRouteEntry& other) const {
        return destination_prefix == other.destination_prefix &&
               subnet_mask == other.subnet_mask &&
               metric == other.metric &&
               next_hop_ips == other.next_hop_ips &&
               egress_interface_ids == other.egress_interface_ids;
    }

    bool operator<(const SpfRouteEntry& other) const {
        if (destination_prefix < other.destination_prefix) return true;
        if (destination_prefix > other.destination_prefix) return false;
        if (subnet_mask < other.subnet_mask) return true;
        if (subnet_mask > other.subnet_mask) return false;
        if (metric < other.metric) return true;
        if (metric > other.metric) return false;
        return next_hop_ips < other.next_hop_ips; // Arbitrary tie-break for set ordering
    }
};


// Structure to hold path information to a node (SystemID) in the SPF tree
struct SpfNodePathInfo {
    SystemID node_id{};
    uint32_t total_metric = std::numeric_limits<uint32_t>::max();
    std::set<SystemID> predecessors{}; // SystemIDs of previous hops on shortest path(s)
    
    // For first hop determination from local_system_id_
    std::set<IpAddress> first_hop_router_ips{}; // IP address(es) of the direct neighbor(s)
    std::set<uint32_t> local_egress_interface_ids{}; // Local interface(s) to reach the first_hop_router_ips

    bool operator>(const SpfNodePathInfo& other) const { // For min-priority queue
        return total_metric > other.total_metric;
    }
     bool operator<(const SpfNodePathInfo& other) const {
        if (total_metric < other.total_metric) return true;
        if (total_metric > other.total_metric) return false;
        return node_id < other.node_id; // Tie-breaking for stable ordering
    }
};


class IsisSpfCalculator {
public:
    IsisSpfCalculator(const SystemID& local_sys_id, IsisLevel level, const IsisLsdb* lsdb);

    // Calculates SPF and returns a list of routes.
    std::vector<SpfRouteEntry> calculate_spf() const;

    // Calculates Multicast SPF and returns a list of multicast routes.
    std::vector<MulticastRouteEntry> calculate_multicast_spf(
        const std::map<SystemID, SpfNodePathInfo>& unicast_spf_results) const;

private:
    // Helper to parse relevant TLVs from an LSP.
    void parse_lsp_links(const LinkStatePdu& lsp, 
                         std::map<SystemID, uint32_t>& out_neighbors, 
                         std::vector<IpReachabilityInfo>& out_ip_prefixes) const;

    // Helper to convert prefix length to subnet mask
    IpAddress calculate_subnet_mask(uint8_t prefix_len) const;

    // Helper to get direct neighbor info (IP and interface) if available
    // This might need access to IsisInterfaceManager or adjacencies passed some other way.
    // For now, assume this info is discovered during SPF from LSPs or pre-populated.
    struct DirectNeighborInfo {
        IpAddress ip;
        uint32_t interface_id;
    };
    std::vector<DirectNeighborInfo> get_direct_neighbor_info(const SystemID& neighbor_id) const;

    // Helper to parse multicast specific TLVs from an LSP.
    void parse_lsp_multicast_info(const LinkStatePdu& lsp,
                                  bool& out_is_multicast_capable,
                                  std::vector<MulticastGroupAddressInfo>& out_advertised_groups) const;


    SystemID local_system_id_;
    IsisLevel level_;
    const IsisLsdb* lsdb_; // Non-owning pointer
    // Consider adding IsisInterfaceManager* if needed for RPF interface determination for local system
    // const IsisInterfaceManager* if_mgr_; 
};


// Removed MulticastRouteEntry from here as it's moved to the top.

} // namespace isis
} // namespace netflow

#endif // NETFLOW_ISIS_SPF_CALCULATOR_HPP
