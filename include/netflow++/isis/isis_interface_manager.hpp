#ifndef NETFLOW_ISIS_INTERFACE_MANAGER_HPP
#define NETFLOW_ISIS_INTERFACE_MANAGER_HPP

#include "netflow++/isis/isis_common.hpp" // Provides SystemID, AreaAddress, Tlv, std::array
#include "netflow++/isis/isis_pdu.hpp"     // Provides PDU structures
#include "netflow++/interface_manager.hpp" // Assumed to exist and be self-contained
#include "netflow++/packet.hpp"            // For MacAddress, IpAddress - Assumed to exist and be self-contained

#include <cstdint>    // For uintX_t types
#include <string>     // For std::string (though direct usage is minimal here, often via other headers)
#include <vector>     // For std::vector
#include <map>        // For std::map
#include <mutex>      // For std::mutex
#include <chrono>     // For std::chrono types
#include <functional> // For std::function
#include <optional>   // For std::optional
// <array> is included via isis_common.hpp

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
};

// Enum for Adjacency State
enum class AdjacencyState {
    DOWN,
    INITIALIZING,
    UP
};

struct IsisInterfaceConfig {
    uint32_t interface_id = 0;
    bool isis_enabled = false;
    SystemID system_id{};
    AreaAddress area_id{};
    IsisLevel level = IsisLevel::L1_L2;
    CircuitType circuit_type = CircuitType::BROADCAST;
    uint16_t hello_interval_seconds = 10;
    uint16_t holding_timer_multiplier = 3;
    uint8_t priority = 64;
    uint16_t lsp_retransmission_interval_seconds = 5;
    MacAddress p2p_destination_mac = MacAddress("01:80:C2:00:00:14"); // Example
};

struct IsisAdjacency {
    uint32_t interface_id = 0;
    AdjacencyState state = AdjacencyState::DOWN;
    SystemID neighbor_system_id{};
    MacAddress neighbor_mac_address{};
    std::optional<SystemID> lan_id{}; // LAN ID from Hello, if applicable
    IsisLevel level_established = IsisLevel::NONE;
    std::chrono::steady_clock::time_point last_hello_received_time{};
    uint16_t holding_time_seconds = 0;
    uint8_t neighbor_priority = 0;
    std::optional<IpAddress> neighbor_ip_address{};
    bool three_way_match = false;
};

struct IsisInterfaceState {
    IsisInterfaceConfig config{};
    std::chrono::steady_clock::time_point next_hello_send_time{};
    std::map<SystemID, IsisAdjacency> adjacencies{}; // Key: Neighbor SystemID
    bool is_dis = false;
    // current_dis_lan_id stores the LAN ID (7 bytes) of the current DIS on this interface.
    // SystemID is 6 bytes. This should be std::array<uint8_t, 7> if it holds a 7-byte LAN ID.
    // For now, keeping as SystemID based on original code, assuming it means DIS's SystemID part.
    SystemID current_dis_system_id{}; // SystemID of the DIS
    uint8_t current_dis_pseudonode_id = 0; // Pseudonode ID of the DIS

    // actual_lan_id is this interface's own LAN ID if it were to become DIS.
    // It's SystemID + a self-assigned pseudonode ID.
    std::array<uint8_t, SYSTEM_ID_LENGTH + 1> actual_lan_id{};
};


class IsisInterfaceManager {
public:
    IsisInterfaceManager(netflow::InterfaceManager& if_mgr,
                         const SystemID& local_sys_id,
                         const std::vector<AreaAddress>& local_areas);

    void configure_interface(uint32_t interface_id, const IsisInterfaceConfig& config);
    void disable_isis_on_interface(uint32_t interface_id);
    std::optional<IsisInterfaceConfig> get_interface_config(uint32_t interface_id) const;
    std::optional<IsisInterfaceState> get_interface_state(uint32_t interface_id) const;

    void handle_received_hello(uint32_t interface_id,
                               const MacAddress& source_mac,
                               const CommonPduHeader& common_header,
                               const LanHelloPdu& pdu);
    void handle_received_hello(uint32_t interface_id,
                               const MacAddress& source_mac,
                               const CommonPduHeader& common_header,
                               const PointToPointHelloPdu& pdu);

    void periodic_tasks();

    void register_send_pdu_callback(std::function<void(uint32_t, const MacAddress&, const std::vector<uint8_t>&)> cb);
    void register_adjacency_change_callback(std::function<void(const IsisAdjacency&, bool is_up)> cb);

    std::vector<IsisAdjacency> get_adjacencies(uint32_t interface_id) const;
    std::vector<IsisAdjacency> get_all_adjacencies_by_level(IsisLevel level) const;
    bool is_interface_up_and_isis_enabled(uint32_t interface_id) const;
    bool is_elected_dis(uint32_t interface_id) const;
    std::optional<std::array<uint8_t, SYSTEM_ID_LENGTH + 1>> get_lan_id(uint32_t interface_id) const;

private:
    void send_hello(uint32_t interface_id, IsisInterfaceState& if_state);
    void check_adjacency_timeouts(uint32_t interface_id, IsisInterfaceState& if_state);
    void perform_dis_election(uint32_t interface_id, IsisInterfaceState& if_state);
    void update_adjacency_state(IsisAdjacency& adj, AdjacencyState new_state, bool is_lan_adj = false);
    std::optional<IpAddress> extract_ip_address_from_tlvs(const std::vector<Tlv>& tlvs) const;
    bool check_area_match(const AreaAddress& local_area, const std::vector<Tlv>& tlvs) const;
    bool check_p2p_adjacency_three_way_state(const PointToPointHelloPdu& received_hello, const IsisInterfaceState& if_state) const;

    mutable std::mutex mutex_;
    std::map<uint32_t, IsisInterfaceState> interface_states_;
    netflow::InterfaceManager& underlying_interface_manager_;
    SystemID local_system_id_;
    std::vector<AreaAddress> local_area_addresses_;

    std::function<void(uint32_t, const MacAddress&, const std::vector<uint8_t>&)> send_pdu_callback_;
    std::function<void(const IsisAdjacency&, bool is_up)> adjacency_change_callback_;

    const MacAddress ALL_L1_ISS_MAC = MacAddress("01:80:C2:00:00:14");
    const MacAddress ALL_L2_ISS_MAC = MacAddress("01:80:C2:00:00:15");
    const MacAddress ALL_ISS_MAC = MacAddress("09:00:2B:00:00:05");
};

} // namespace isis
} // namespace netflow

#endif // NETFLOW_ISIS_INTERFACE_MANAGER_HPP
