#ifndef NETFLOW_ISIS_INTERFACE_MANAGER_HPP
#define NETFLOW_ISIS_INTERFACE_MANAGER_HPP

#include "netflow++/isis/isis_common.hpp"
#include "netflow++/isis/isis_pdu.hpp"
#include "netflow++/interface_manager.hpp" // Assumed to exist
#include "netflow++/packet.hpp"         // For MacAddress, IpAddress - Assumed to exist

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <chrono>
#include <functional>
#include <optional> // For std::optional

namespace netflow {
namespace isis {

// Enum for IS-IS Level capability
enum class IsisLevel {
    NONE,
    L1,
    L2,
    L1_L2
};

// Enum for Circuit Type
enum class CircuitType {
    P2P,
    BROADCAST
    // NBMA could be another type
};

// Enum for Adjacency State
enum class AdjacencyState {
    DOWN,
    INITIALIZING, // Received Hello from neighbor
    UP            // Adjacency established (e.g. 2-way for LAN, or P2P up)
};

// Enum for state reported by neighbor in P2P Adjacency TLV
enum class AdjacencyStateReportedByNeighbor {
    UNKNOWN,
    DOWN_NEIGHBOR,
    INITIALIZING_NEIGHBOR,
    UP_NEIGHBOR
};

struct IsisInterfaceConfig {
    uint32_t interface_id = 0;
    bool isis_enabled = false;
    SystemID system_id{}; // Local system ID for this interface instance (often same as global)
    AreaAddress area_id{};   // Primary area ID for L1 on this interface
    IsisLevel level = IsisLevel::L1_L2;
    CircuitType circuit_type = CircuitType::BROADCAST; // Default, may be auto-detected
    uint16_t hello_interval_seconds = 10;
    uint16_t holding_timer_multiplier = 3; // holding_time = hello_interval * multiplier
    uint8_t priority = 64;                 // For DIS election on LANs
    uint16_t lsp_retransmission_interval_seconds = 5; // Not used in this manager directly, but for overall ISIS
    MacAddress p2p_destination_mac = MacAddress("01:80:C2:00:00:14"); // Default for L1. L2 is 01:80:C2:00:00:15.
                                                                    // All IS-IS Routers: 09:00:2B:00:00:05 (deprecated by 802.1Q)
                                                                    // Consider using specific AllL1ISs, AllL2ISs, AllP2PISs MACs
};

struct IsisAdjacency {
    uint32_t interface_id = 0; // Interface this adjacency belongs to
    AdjacencyState state = AdjacencyState::DOWN;
    SystemID neighbor_system_id{};
    MacAddress neighbor_mac_address{}; // For LANs, or source MAC for P2P Ethernet
    std::optional<SystemID> lan_id{};   // Full LAN ID (DIS SystemID + PseudonodeID) if LAN
                                        // For P2P, this might not be used or store neighbor's SystemID
    IsisLevel level_established = IsisLevel::NONE; // L1, L2, or L1_L2 if both match
    std::chrono::steady_clock::time_point last_hello_received_time{};
    uint16_t holding_time_seconds = 0;
    uint8_t neighbor_priority = 0; // If LAN adjacency
    std::optional<IpAddress> neighbor_ip_address{}; // From IP Interface Address TLV in Hello
    bool three_way_match = false; // For P2P, indicates a three-way state match
    // Fields for P2P Adjacency State TLV (Type 240)
    uint32_t neighbor_extended_local_circuit_id = 0; // Neighbor's ELCID, learned from their Hello
    bool neighbor_elcid_known = false;               // Flag indicating if neighbor's ELCID has been learned
    AdjacencyStateReportedByNeighbor reported_state_by_neighbor = AdjacencyStateReportedByNeighbor::UNKNOWN; // State of our adj as reported by neighbor in their P2P Hello TLV
};

struct IsisInterfaceState {
    IsisInterfaceConfig config{};
    std::chrono::steady_clock::time_point next_hello_send_time{};
    // Key: Neighbor SystemID. Note: On a LAN, a neighbor might have multiple levels.
    // This might need adjustment if a single neighbor SystemID can have separate L1 and L2 adjacencies on the same interface.
    // For now, assume one adjacency object per neighbor system ID, level_established indicates L1/L2/Both.
    std::map<SystemID, IsisAdjacency> adjacencies{};
    bool is_dis = false; // If this system is DIS for this LAN segment
    SystemID current_dis_lan_id{}; // SystemID (6 bytes) + Pseudonode ID (1 byte)
                                   // Valid if circuit_type is BROADCAST and DIS has been elected.
                                   // Stored as 7 bytes, though SystemID type is 6. Use std::array<uint8_t, 7> for this.
    std::array<uint8_t, 7> actual_lan_id{}; // Our own LAN ID if we are DIS.
};


class IsisInterfaceManager {
public:
    IsisInterfaceManager(netflow::InterfaceManager& if_mgr, 
                         const SystemID& local_sys_id,
                         const std::vector<AreaAddress>& local_areas);

    // Configuration Methods
    void configure_interface(uint32_t interface_id, const IsisInterfaceConfig& config);
    void disable_isis_on_interface(uint32_t interface_id);
    std::optional<IsisInterfaceConfig> get_interface_config(uint32_t interface_id) const;
    std::optional<IsisInterfaceState> get_interface_state(uint32_t interface_id) const;


    // PDU Handling Methods
    void handle_received_hello(uint32_t interface_id, 
                               const MacAddress& source_mac, 
                               const CommonPduHeader& common_header, 
                               const LanHelloPdu& pdu);
    void handle_received_hello(uint32_t interface_id, 
                               const MacAddress& source_mac, 
                               const CommonPduHeader& common_header, 
                               const PointToPointHelloPdu& pdu);

    // Periodic Processing Method
    void periodic_tasks();

    // Callback Registration
    void register_send_pdu_callback(std::function<void(uint32_t, const MacAddress&, const std::vector<uint8_t>&)> cb);
    void register_adjacency_change_callback(std::function<void(const IsisAdjacency&, bool is_up)> cb);

    // Query Methods
    std::vector<IsisAdjacency> get_adjacencies(uint32_t interface_id) const;
    std::vector<IsisAdjacency> get_all_adjacencies_by_level(IsisLevel level) const;
    bool is_interface_up_and_isis_enabled(uint32_t interface_id) const;
    bool is_elected_dis(uint32_t interface_id) const;
    std::optional<std::array<uint8_t, 7>> get_lan_id(uint32_t interface_id) const;
    std::optional<MacAddress> get_dis_mac_address(uint32_t interface_id) const;


private:
    // Helper methods
    void send_hello(uint32_t interface_id, IsisInterfaceState& if_state);
    void check_adjacency_timeouts(uint32_t interface_id, IsisInterfaceState& if_state);
    void perform_dis_election(uint32_t interface_id, IsisInterfaceState& if_state);
    void update_adjacency_state(IsisAdjacency& adj, AdjacencyState new_state, bool is_lan_adj = false);
    std::optional<IpAddress> extract_ip_address_from_tlvs(const std::vector<TLV>& tlvs) const;
    bool check_area_match(const AreaAddress& local_area, const std::vector<TLV>& tlvs) const;
    // P2P Adjacency specific logic
    bool check_p2p_adjacency_three_way_state(const PointToPointHelloPdu& received_hello, const IsisInterfaceState& if_state) const;


    mutable std::mutex mutex_; // `mutable` to allow locking in const methods for cache or internal state updates not visible to caller
    std::map<uint32_t, IsisInterfaceState> interface_states_;
    netflow::InterfaceManager& underlying_interface_manager_;
    SystemID local_system_id_;
    std::vector<AreaAddress> local_area_addresses_; // Global list of areas this IS belongs to

    std::function<void(uint32_t, const MacAddress&, const std::vector<uint8_t>&)> send_pdu_callback_;
    std::function<void(const IsisAdjacency&, bool is_up)> adjacency_change_callback_;

    // Constants for MAC addresses
    const MacAddress ALL_L1_ISS_MAC = MacAddress("01:80:C2:00:00:14");
    const MacAddress ALL_L2_ISS_MAC = MacAddress("01:80:C2:00:00:15");
    const MacAddress ALL_ISS_MAC = MacAddress("09:00:2B:00:00:05"); // Potentially deprecated by IEEE 802.1Q for ISIS
};

} // namespace isis
} // namespace netflow

#endif // NETFLOW_ISIS_INTERFACE_MANAGER_HPP
