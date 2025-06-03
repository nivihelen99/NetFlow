#include "netflow++/isis/isis_interface_manager.hpp"
#include "netflow++/isis/isis_pdu_constants.hpp"
#include "netflow++/byte_swap.hpp"
#include "netflow++/isis/isis_utils.hpp" // Added for BufferReader and parsing utilities

#include <algorithm> // For std::find_if, std::remove_if
#include <iostream> // For temporary logging/debugging
#include <cstring> // For std::memcpy if parse_bytes is used locally (it's now in isis_utils)

// Placeholder for actual packet serialization/deserialization functions if not fully in isis_pdu.cpp
// For now, assume isis_pdu.hpp and isis_pdu.cpp provide necessary serialize/parse functions.

namespace netflow {
namespace isis {

// Stubs for serialize_lan_hello_pdu and serialize_point_to_point_hello_pdu are kept here
// as they are specific to this manager's sending logic, not general utils.
// However, their declarations should ideally be in isis_pdu.hpp or a dedicated serialization header.
// TODO: Move declarations to appropriate header if these become full implementations.
std::vector<uint8_t> serialize_lan_hello_pdu(const LanHelloPdu& pdu) {
    // std::cout << "STUB: serialize_lan_hello_pdu called" << std::endl;
    std::vector<uint8_t> dummy_pdu_data;
    dummy_pdu_data.push_back(pdu.commonHeader.pduType);
    dummy_pdu_data.push_back(0xDE);
    dummy_pdu_data.push_back(0xAD);
    dummy_pdu_data.push_back(0xBF);
    return dummy_pdu_data;
}

std::vector<uint8_t> serialize_point_to_point_hello_pdu(const PointToPointHelloPdu& pdu) {
    // std::cout << "STUB: serialize_point_to_point_hello_pdu called" << std::endl;
    std::vector<uint8_t> dummy_pdu_data;
    dummy_pdu_data.push_back(pdu.commonHeader.pduType);
    dummy_pdu_data.push_back(0xCA);
    dummy_pdu_data.push_back(0xFE);
    return dummy_pdu_data;
}

// Helper to convert SystemID to string for map keys if needed (not directly needed for std::map<SystemID, ...>)
// std::string system_id_to_string(const SystemID& id) {
//     return std::string(reinterpret_cast<const char*>(id.data()), id.size());
// }


IsisInterfaceManager::IsisInterfaceManager(
    netflow::InterfaceManager& if_mgr,
    const SystemID& local_sys_id,
    const std::vector<AreaAddress>& local_areas)
    : underlying_interface_manager_(if_mgr),
      local_system_id_(local_sys_id),
      local_area_addresses_(local_areas),
      send_pdu_callback_(nullptr),
      adjacency_change_callback_(nullptr) {
}

void IsisInterfaceManager::configure_interface(uint32_t interface_id, const IsisInterfaceConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto if_config_opt = underlying_interface_manager_.get_port_config(interface_id);
    if (!if_config_opt) {
        // std::cerr << "IsisInterfaceManager: Cannot configure non-existent interface " << interface_id << std::endl;
        return;
    }

    IsisInterfaceState if_state;
    if_state.config = config;
    if_state.config.interface_id = interface_id; // Ensure interface_id is set in stored config
    if_state.config.system_id = local_system_id_; // Ensure local system ID is used from manager's global config

    // If circuit type is not explicitly P2P and it's Ethernet, assume BROADCAST
    // This logic might be more complex based on media type from if_config_opt
    // Note: PortConfig does not have 'media_type'. Assuming default to BROADCAST or using config value.
    // For now, let's simplify this part to avoid relying on a non-existent 'media_type'.
    // A more robust solution would involve checking interface capabilities if needed.
    if (config.circuit_type != CircuitType::P2P) { // Simplified: if not P2P, assume BROADCAST for ISIS.
        if_state.config.circuit_type = CircuitType::BROADCAST;
    } else {
        if_state.config.circuit_type = config.circuit_type; // Use configured P2P
    }


    if_state.next_hello_send_time = std::chrono::steady_clock::now(); // Send first hello immediately
    interface_states_[interface_id] = if_state;
    // std::cout << "ISIS configured on interface " << interface_id << std::endl;
}

void IsisInterfaceManager::disable_isis_on_interface(uint32_t interface_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = interface_states_.find(interface_id);
    if (it != interface_states_.end()) {
        // Call adjacency down for all adjacencies on this interface
        for (auto& adj_pair : it->second.adjacencies) {
            if (adj_pair.second.state != AdjacencyState::DOWN) {
                update_adjacency_state(adj_pair.second, AdjacencyState::DOWN, it->second.config.circuit_type == CircuitType::BROADCAST);
            }
        }
        interface_states_.erase(it);
        // std::cout << "ISIS disabled on interface " << interface_id << std::endl;
    }
}

std::optional<IsisInterfaceConfig> IsisInterfaceManager::get_interface_config(uint32_t interface_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = interface_states_.find(interface_id);
    if (it != interface_states_.end()) {
        return it->second.config;
    }
    return std::nullopt;
}

std::optional<IsisInterfaceState> IsisInterfaceManager::get_interface_state(uint32_t interface_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = interface_states_.find(interface_id);
    if (it != interface_states_.end()) {
        return it->second;
    }
    return std::nullopt;
}


void IsisInterfaceManager::register_send_pdu_callback(std::function<void(uint32_t, const MacAddress&, const std::vector<uint8_t>&)> cb) {
    send_pdu_callback_ = cb;
}

void IsisInterfaceManager::register_adjacency_change_callback(std::function<void(const IsisAdjacency&, bool is_up)> cb) {
    adjacency_change_callback_ = cb;
}

std::vector<IsisAdjacency> IsisInterfaceManager::get_adjacencies(uint32_t interface_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<IsisAdjacency> adjs;
    auto it = interface_states_.find(interface_id);
    if (it != interface_states_.end()) {
        for (const auto& pair : it->second.adjacencies) {
            adjs.push_back(pair.second);
        }
    }
    return adjs;
}

std::vector<IsisAdjacency> IsisInterfaceManager::get_all_adjacencies_by_level(IsisLevel level) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<IsisAdjacency> adjs;
    for (const auto& if_pair : interface_states_) {
        for (const auto& adj_pair : if_pair.second.adjacencies) {
            if (adj_pair.second.state == AdjacencyState::UP) {
                if (level == IsisLevel::L1 && (adj_pair.second.level_established == IsisLevel::L1 || adj_pair.second.level_established == IsisLevel::L1_L2)) {
                    adjs.push_back(adj_pair.second);
                } else if (level == IsisLevel::L2 && (adj_pair.second.level_established == IsisLevel::L2 || adj_pair.second.level_established == IsisLevel::L1_L2)) {
                    adjs.push_back(adj_pair.second);
                } else if (level == IsisLevel::L1_L2 && adj_pair.second.level_established == IsisLevel::L1_L2) {
                     adjs.push_back(adj_pair.second);
                } else if (level == IsisLevel::NONE) { // Should not happen for UP adj
                    adjs.push_back(adj_pair.second);
                }
            }
        }
    }
    return adjs;
}


bool IsisInterfaceManager::is_interface_up_and_isis_enabled(uint32_t interface_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto if_config_opt = underlying_interface_manager_.get_port_config(interface_id);
    // Check if config exists, if port is admin up, and if link is physically up
    if (!if_config_opt || !if_config_opt->admin_up || !underlying_interface_manager_.is_port_link_up(interface_id)) {
        return false;
    }
    auto it = interface_states_.find(interface_id);
    return it != interface_states_.end() && it->second.config.isis_enabled;
}

bool IsisInterfaceManager::is_elected_dis(uint32_t interface_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = interface_states_.find(interface_id);
    if (it != interface_states_.end()) {
        return it->second.is_dis;
    }
    return false;
}

std::optional<std::array<uint8_t, 7>> IsisInterfaceManager::get_lan_id(uint32_t interface_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = interface_states_.find(interface_id);
    if (it != interface_states_.end() && it->second.config.circuit_type == CircuitType::BROADCAST) {
         if (it->second.is_dis) { // If we are DIS, our LAN ID is authoritative
            return it->second.actual_lan_id;
         }
         // If not DIS, current_dis_lan_id stores the elected DIS's LAN ID
         // Check if current_dis_lan_id is non-zero (SystemID part)
         bool is_zero = true;
         for(size_t i=0; i < 6; ++i) if(it->second.current_dis_lan_id[i] != 0) is_zero = false;
         if(!is_zero) return it->second.current_dis_lan_id;
    }
    return std::nullopt;
}

std::vector<uint32_t> IsisInterfaceManager::get_interface_ids_by_level(IsisLevel level) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<uint32_t> result_ids;
    for (const auto& pair : interface_states_) {
        const IsisInterfaceState& if_state = pair.second;
        if (if_state.config.isis_enabled) {
            if (level == IsisLevel::L1 && (if_state.config.level == IsisLevel::L1 || if_state.config.level == IsisLevel::L1_L2)) {
                result_ids.push_back(pair.first);
            } else if (level == IsisLevel::L2 && (if_state.config.level == IsisLevel::L2 || if_state.config.level == IsisLevel::L1_L2)) {
                result_ids.push_back(pair.first);
            } else if (level == IsisLevel::L1_L2 && if_state.config.level == IsisLevel::L1_L2) { // Only if interface is strictly L1_L2 for this query
                result_ids.push_back(pair.first);
            }
            // Not handling IsisLevel::NONE as it implies no specific level query
        }
    }
    return result_ids;
}


void IsisInterfaceManager::update_adjacency_state(IsisAdjacency& adj, AdjacencyState new_state, bool is_lan_adj) {
    if (adj.state == new_state) {
        return;
    }
    AdjacencyState old_state = adj.state;
    adj.state = new_state;

    // std::cout << "Adj " << system_id_to_string(adj.neighbor_system_id) << " on if " << adj.interface_id
    //           << " changed state from " << static_cast<int>(old_state) << " to " << static_cast<int>(new_state) << std::endl;

    if (adjacency_change_callback_) {
        adjacency_change_callback_(adj, new_state == AdjacencyState::UP);
    }

    // If adjacency is going down, and it was a LAN adjacency, trigger DIS re-election
    if (old_state == AdjacencyState::UP && new_state != AdjacencyState::UP && is_lan_adj) {
        auto it = interface_states_.find(adj.interface_id);
        if (it != interface_states_.end()) {
            // std::cout << "Triggering DIS re-election on if " << adj.interface_id << " due to adjacency down." << std::endl;
            perform_dis_election(adj.interface_id, it->second);
        }
    }
}

// --- PDU Handling ---
void IsisInterfaceManager::handle_received_hello(uint32_t interface_id,
                                   const MacAddress& source_mac,
                                   const CommonPduHeader& common_header,
                                   const LanHelloPdu& pdu) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto if_state_it = interface_states_.find(interface_id);
    if (if_state_it == interface_states_.end() || !if_state_it->second.config.isis_enabled) {
        return; // ISIS not enabled on this interface
    }
    IsisInterfaceState& if_state = if_state_it->second;

    if (if_state.config.circuit_type != CircuitType::BROADCAST) {
        // std::cerr << "Received LAN Hello on non-broadcast interface " << interface_id << std::endl;
        return;
    }

    // Basic validation
    if (common_header.version != 1 || common_header.versionProtocolIdExtension != 1) {
        // std::cerr << "Invalid version in LAN Hello from " << source_mac.to_string() << std::endl;
        return;
    }
    if (pdu.sourceId == local_system_id_) { // common_header.idLength will tell actual length of sourceId
        return; // Loopback, ignore
    }

    IsisLevel hello_level = IsisLevel::NONE;
    if (common_header.pduType == L1_LAN_IIH_TYPE) hello_level = IsisLevel::L1;
    else if (common_header.pduType == L2_LAN_IIH_TYPE) hello_level = IsisLevel::L2;
    else return; // Not L1 or L2 LAN Hello

    // Check if our interface level matches Hello level
    bool level_match = false;
    if (hello_level == IsisLevel::L1 && (if_state.config.level == IsisLevel::L1 || if_state.config.level == IsisLevel::L1_L2)) {
        level_match = true;
    } else if (hello_level == IsisLevel::L2 && (if_state.config.level == IsisLevel::L2 || if_state.config.level == IsisLevel::L1_L2)) {
        level_match = true;
    }
    if (!level_match) {
        // std::cout << "Level mismatch for LAN Hello from " << source_mac.to_string() << " on if " << interface_id << std::endl;
        return;
    }
    
    // Area Address check for L1 Hellos
    if (hello_level == IsisLevel::L1) {
        const AreaAddress* area_to_use_for_check = &if_state.config.area_id;
        if (if_state.config.area_id.empty()) { // Interface has no specific L1 area
            if (!local_area_addresses_.empty()) {
                area_to_use_for_check = &local_area_addresses_[0]; // Use first global area
            } else {
                // This router has no L1 area configured at all. Cannot form L1 adjacency.
                // std::cout << "L1 LAN Hello on if " << interface_id << " but this router has no L1 area configured." << std::endl;
                // If an old adjacency existed, ensure it's removed or downed.
                auto existing_adj_it = if_state.adjacencies.find(pdu.sourceId);
                if (existing_adj_it != if_state.adjacencies.end()) {
                    update_adjacency_state(existing_adj_it->second, AdjacencyState::DOWN, true);
                    // Consider if_state.adjacencies.erase(existing_adj_it);
                }
                return; // Reject Hello
            }
        }

        if (area_to_use_for_check->empty() || !check_area_match(*area_to_use_for_check, pdu.tlvs)) {
            // std::cout << "Area mismatch for L1 LAN Hello from " << source_mac.to_string() << " on if " << interface_id << std::endl;
            auto existing_adj_it = if_state.adjacencies.find(pdu.sourceId);
            if (existing_adj_it != if_state.adjacencies.end()) {
                update_adjacency_state(existing_adj_it->second, AdjacencyState::DOWN, true);
                // Consider if_state.adjacencies.erase(existing_adj_it);
            }
            return; // Reject Hello
        }
    }

    auto adj_it = if_state.adjacencies.find(pdu.sourceId);
    bool new_adjacency = (adj_it == if_state.adjacencies.end());
    IsisAdjacency* adj;

    if (new_adjacency) {
        IsisAdjacency new_adj;
        new_adj.interface_id = interface_id;
        new_adj.neighbor_system_id = pdu.sourceId;
        if_state.adjacencies[pdu.sourceId] = new_adj;
        adj = &if_state.adjacencies[pdu.sourceId];
        // std::cout << "New potential LAN adjacency with " << system_id_to_string(pdu.sourceId) << " on if " << interface_id << std::endl;
    } else {
        adj = &adj_it->second;
    }

    adj->neighbor_mac_address = source_mac;
    adj->holding_time_seconds = ntohs(pdu.holdingTime); // Assuming pdu fields are raw network order
    adj->last_hello_received_time = std::chrono::steady_clock::now();
    adj->neighbor_priority = pdu.priority;
    adj->neighbor_learned_lan_id = pdu.lanId; // Store the received 7-byte LAN ID


    // Determine established level
    if (adj->level_established == IsisLevel::NONE) {
        adj->level_established = hello_level;
    } else if (adj->level_established == IsisLevel::L1 && hello_level == IsisLevel::L2) {
        if (if_state.config.level == IsisLevel::L1_L2) adj->level_established = IsisLevel::L1_L2;
    } else if (adj->level_established == IsisLevel::L2 && hello_level == IsisLevel::L1) {
        if (if_state.config.level == IsisLevel::L1_L2) adj->level_established = IsisLevel::L1_L2;
    }
    // If already L1_L2, or same level received again, no change to adj->level_established needed.

    adj->neighbor_ip_address = extract_ip_address_from_tlvs(pdu.tlvs);

    // Adjacency state transition: For LAN, receiving a Hello is enough to go to UP.
    // True 2-way check involves seeing ourselves in their IS Neighbors TLV (TLV Type 2).
    // For now, a simpler model: if we receive their Hello, they are at least INITIALIZING/UP from our PoV.
    bool two_way_confirmed = false;
    // The redundant L1 area check block that was here due to previous diff issue is now consolidated above.

    for(const auto& tlv : pdu.tlvs) {
        if (tlv.type == IS_NEIGHBORS_LAN_TLV_TYPE) {
            auto our_if_config_opt = underlying_interface_manager_.get_port_config(interface_id);
            if (our_if_config_opt) { // Check if config exists
                // MAC address in PortConfig is `MacAddress mac_address;`
                // MacAddress struct has `uint8_t bytes[6];`
                bool mac_is_non_zero = false; // Check if our MAC is not all zeros
                for(int k=0; k<6; ++k) if(our_if_config_opt->mac_address.bytes[k] != 0) mac_is_non_zero = true;

                if (mac_is_non_zero) {
                    for(size_t i = 0; (i + 6) <= tlv.value.size(); i += 6) {
                        if (std::equal(our_if_config_opt->mac_address.bytes,
                                       our_if_config_opt->mac_address.bytes + 6,
                                       tlv.value.data() + i)) { // Use .data() for vector
                            two_way_confirmed = true;
                            break;
                        }
                    }
                }
            }
            if(two_way_confirmed) break;
        }
    }
    
    if (two_way_confirmed) {
         update_adjacency_state(*adj, AdjacencyState::UP, true);
    } else {
        // If already UP and lost 2-way, go to INITIALIZING. Otherwise, stay/go INITIALIZING.
        // Standard: if you see neighbor but don't see yourself listed, state is Initializing.
        // If it was UP and we are no longer listed, it means they dropped us.
        if (adj->state == AdjacencyState::UP) {
            update_adjacency_state(*adj, AdjacencyState::INITIALIZING, true);
        } else if (adj->state == AdjacencyState::DOWN) { // New or previously down adj
            update_adjacency_state(*adj, AdjacencyState::INITIALIZING, true);
        }
        // If already INITIALIZING and still no two-way, it remains INITIALIZING until timeout or two-way.
    }

    // Populate adj->lan_id from pdu.lanId. This is the DIS's LAN ID.
    // If pdu.lanId is valid (e.g. not all zeros if that's a convention for "unknown")
    // This logic was for the old adj->lan_id (SystemID type).
    // Now, neighbor_learned_lan_id (array<uint8_t, 7>) is directly assigned pdu.lanId.
    // The check for pdu_lan_id_is_valid can still be useful before using its content in DIS election.
    // bool pdu_lan_id_is_valid = false;
    // for(size_t i=0; i<6; ++i) { /* check if pdu.lanId systemID part is non-zero */ }
    // if(pdu_lan_id_is_valid) {
    //    // adj->neighbor_learned_lan_id = pdu.lanId; // Already done above.
    // }


    // If adjacency came up or neighbor priority changed, DIS election might be affected.
    if (adj->state == AdjacencyState::UP) {
        perform_dis_election(interface_id, if_state);
    }
}

void IsisInterfaceManager::handle_received_hello(uint32_t interface_id,
                                   const MacAddress& source_mac,
                                   const CommonPduHeader& common_header,
                                   const PointToPointHelloPdu& pdu) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto if_state_it = interface_states_.find(interface_id);
    if (if_state_it == interface_states_.end() || !if_state_it->second.config.isis_enabled) {
        return;
    }
    IsisInterfaceState& if_state = if_state_it->second;

    if (if_state.config.circuit_type != CircuitType::P2P) {
        // std::cerr << "Received P2P Hello on non-P2P interface " << interface_id << std::endl;
        return;
    }
    if (common_header.version != 1 || common_header.versionProtocolIdExtension != 1) return;
    if (pdu.sourceId == local_system_id_) return; // Loopback

    // For P2P, level is implicitly L1/L2 based on configuration, no L1/L2 specific PDU types for PTP IIH
    // The PTP IIH PDU Type (0x11) is used for L1, L2 or L1_L2.
    // circuitType field in PTP IIH (0x01=L1, 0x02=L2, 0x03=L1/L2) indicates sender's capability on this circuit.
    IsisLevel pdu_circuit_level_capability = IsisLevel::NONE;
    if (pdu.circuitType == 0x01) pdu_circuit_level_capability = IsisLevel::L1;
    else if (pdu.circuitType == 0x02) pdu_circuit_level_capability = IsisLevel::L2;
    else if (pdu.circuitType == 0x03) pdu_circuit_level_capability = IsisLevel::L1_L2;

    IsisLevel interface_configured_level = if_state.config.level;
    if (interface_configured_level == IsisLevel::NONE) return;

    // Determine actual level of adjacency based on mutual capability
    IsisLevel effective_adj_level = IsisLevel::NONE;
    if (interface_configured_level == IsisLevel::L1 || interface_configured_level == IsisLevel::L1_L2) {
        if (pdu_circuit_level_capability == IsisLevel::L1 || pdu_circuit_level_capability == IsisLevel::L1_L2) {
            // L1 Area match is critical for L1 adjacency component
            if (!check_area_match(if_state.config.area_id.empty() ? local_area_addresses_[0] : if_state.config.area_id, pdu.tlvs)) {
                // If L1 area mis-match, L1 part of adjacency cannot come up.
                if (interface_configured_level == IsisLevel::L1) return; // Pure L1 interface, reject.
                                                                        // For L1/L2, L2 might still come up.
            } else {
                 effective_adj_level = IsisLevel::L1; // At least L1 can come up
            }
        }
    }
    if (interface_configured_level == IsisLevel::L2 || interface_configured_level == IsisLevel::L1_L2) {
        if (pdu_circuit_level_capability == IsisLevel::L2 || pdu_circuit_level_capability == IsisLevel::L1_L2) {
            if (effective_adj_level == IsisLevel::L1) effective_adj_level = IsisLevel::L1_L2; // Upgrade to L1_L2
            else if (effective_adj_level == IsisLevel::NONE) effective_adj_level = IsisLevel::L2; // Only L2
        }
    }

    if (effective_adj_level == IsisLevel::NONE) { // No compatible level for adjacency
        // std::cout << "No compatible level for P2P adjacency with " << system_id_to_string(pdu.sourceId) << std::endl;
        return;
    }
    
    auto adj_it = if_state.adjacencies.find(pdu.sourceId);
    bool new_adjacency = (adj_it == if_state.adjacencies.end());
    IsisAdjacency* adj;

    if (new_adjacency) {
        IsisAdjacency new_adj;
        new_adj.interface_id = interface_id;
        new_adj.neighbor_system_id = pdu.sourceId;
        if_state.adjacencies[pdu.sourceId] = new_adj; // Add to map
        adj = &if_state.adjacencies[pdu.sourceId]; // Get pointer to map value
        // std::cout << "New potential P2P adjacency with " << system_id_to_string(pdu.sourceId) << " on if " << interface_id << std::endl;
    } else {
        adj = &adj_it->second;
    }

    adj->neighbor_mac_address = source_mac; // Source MAC of P2P Hello
    adj->holding_time_seconds = ntohs(pdu.holdingTime);
    adj->last_hello_received_time = std::chrono::steady_clock::now();
    // adj->level_established = configured_level; // This was an error, effective_adj_level is used below
    adj->neighbor_ip_address = extract_ip_address_from_tlvs(pdu.tlvs);
    // lan_id and neighbor_priority are not typically used for P2P adjacencies.

    // P2P Adjacency State (RFC 5303 / ISO 10589 section 9.6)
    adj->level_established = effective_adj_level; // Update established level
    adj->neighbor_elcid_known = false; // Reset before parsing TLV
    adj->reported_state_by_neighbor = AdjacencyStateReportedByNeighbor::UNKNOWN;

    bool tlv240_found = false;
    uint32_t local_elcid_for_comparison = interface_id; // Our ELCID

    for (const auto& tlv : pdu.tlvs) {
        if (tlv.type == P2P_ADJACENCY_STATE_TLV_TYPE && tlv.length >= 5) { // State (1) + Neighbor's ELCID (4)
            tlv240_found = true;
            uint8_t neighbor_reported_state_byte = tlv.value[0];
            if (neighbor_reported_state_byte == 0x01) adj->reported_state_by_neighbor = AdjacencyStateReportedByNeighbor::DOWN_NEIGHBOR;
            else if (neighbor_reported_state_byte == 0x02) adj->reported_state_by_neighbor = AdjacencyStateReportedByNeighbor::INITIALIZING_NEIGHBOR;
            else if (neighbor_reported_state_byte == 0x03) adj->reported_state_by_neighbor = AdjacencyStateReportedByNeighbor::UP_NEIGHBOR;

            std::memcpy(&adj->neighbor_extended_local_circuit_id, tlv.value.data() + 1, 4);
            adj->neighbor_extended_local_circuit_id = ntohl(adj->neighbor_extended_local_circuit_id);
            adj->neighbor_elcid_known = true;

            if (tlv.length >= 11) { // Neighbor also reports who they see (NeighborSystemID + NeighborELCID)
                SystemID reported_neighbor_sysid;
                std::copy(tlv.value.begin() + 5, tlv.value.begin() + 11, reported_neighbor_sysid.begin());

                uint32_t reported_neighbor_elcid_for_us_net;
                std::memcpy(&reported_neighbor_elcid_for_us_net, tlv.value.data() + 11, 4);
                uint32_t reported_neighbor_elcid_for_us_host = ntohl(reported_neighbor_elcid_for_us_net);

                if (reported_neighbor_sysid == local_system_id_ && reported_neighbor_elcid_for_us_host == local_elcid_for_comparison) {
                    // Neighbor's TLV correctly identifies us.
                    if (adj->reported_state_by_neighbor == AdjacencyStateReportedByNeighbor::UP_NEIGHBOR ||
                        adj->reported_state_by_neighbor == AdjacencyStateReportedByNeighbor::INITIALIZING_NEIGHBOR) {
                        update_adjacency_state(*adj, AdjacencyState::UP, false);
                    } else if (adj->reported_state_by_neighbor == AdjacencyStateReportedByNeighbor::DOWN_NEIGHBOR) {
                        update_adjacency_state(*adj, AdjacencyState::INITIALIZING, false);
                    }
                } else { // Neighbor sees someone else, or us with wrong ELCID
                    update_adjacency_state(*adj, AdjacencyState::INITIALIZING, false);
                }
            } else { // TLV is too short to contain who neighbor sees. Treat as one-way.
                 update_adjacency_state(*adj, AdjacencyState::INITIALIZING, false);
            }
            break;
        }
    }

    if (!tlv240_found) { // No TLV 240 from neighbor
        // This is a one-way declaration. We see them, but they don't confirm seeing us.
        // If adj was UP, it means we lost three-way confirmation.
        if (adj->state == AdjacencyState::UP) {
            update_adjacency_state(*adj, AdjacencyState::DOWN, false); // Or INITIALIZING, but DOWN is safer if TLV disappears
        } else { // Was DOWN or INITIALIZING
            update_adjacency_state(*adj, AdjacencyState::INITIALIZING, false);
        }
    }
}


// --- Periodic Tasks ---
void IsisInterfaceManager::periodic_tasks() {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();

    for (auto& if_pair : interface_states_) {
        uint32_t interface_id = if_pair.first;
        IsisInterfaceState& if_state = if_pair.second;

        if (!if_state.config.isis_enabled || !is_interface_up_and_isis_enabled(interface_id)) {
            // If interface went down or ISIS disabled administratively, ensure all adjacencies are torn down
             for (auto& adj_pair : if_state.adjacencies) {
                if (adj_pair.second.state != AdjacencyState::DOWN) {
                    update_adjacency_state(adj_pair.second, AdjacencyState::DOWN, if_state.config.circuit_type == CircuitType::BROADCAST);
                }
            }
            if_state.adjacencies.clear(); // Clear them after notifying
            if (if_state.is_dis) { // If we were DIS
                if_state.is_dis = false;
                // TODO: Signal DIS change if needed for LSP generation
            }
            continue;
        }
        
        // Send Hellos
        if (now >= if_state.next_hello_send_time) {
            send_hello(interface_id, if_state);
            if_state.next_hello_send_time = now + std::chrono::seconds(if_state.config.hello_interval_seconds);
        }

        // Check Adjacency Timeouts
        check_adjacency_timeouts(interface_id, if_state);

        // Perform DIS Election (if LAN)
        if (if_state.config.circuit_type == CircuitType::BROADCAST) {
            perform_dis_election(interface_id, if_state);
        }
    }
}

// --- Private Helper Methods ---
void IsisInterfaceManager::send_hello(uint32_t interface_id, IsisInterfaceState& if_state) {
    if (!send_pdu_callback_) return;

    auto if_config_opt = underlying_interface_manager_.get_port_config(interface_id);
    if (!if_config_opt || !if_config_opt->admin_up || !underlying_interface_manager_.is_port_link_up(interface_id) || if_config_opt->ip_configurations.empty()) {
        // std::cerr << "Cannot send Hello on if " << interface_id << ": interface not suitable (down, no IP, or no config)." << std::endl;
        return;
    }
    // Assuming primary IP is the first one for Hellos.
    IpAddress source_ip_for_hello = if_config_opt->ip_configurations[0].address;
    // MacAddress source_mac_for_hello = if_config_opt->mac_address; // Available in if_config_opt

    CommonPduHeader common_header;
    common_header.intradomainRoutingProtocolDiscriminator = 0x83; // NLPID for IS-IS
    common_header.versionProtocolIdExtension = 1;
    common_header.version = 1;
    common_header.reserved = 0;
    common_header.idLength = 0; // Indicates 6-byte SystemID
    common_header.maxAreaAddresses = static_cast<uint8_t>(local_area_addresses_.size() > 0 ? local_area_addresses_.size() : (if_state.config.area_id.empty() ? 0 : 1));

    // --- Area Addresses TLV (Type 1) ---
    TLV area_tlv; // Will be populated if needed
    AreaAddressesTlvValue area_tlv_value_content;
    if (!if_state.config.area_id.empty()) {
        area_tlv_value_content.areaAddresses.push_back(if_state.config.area_id);
    } else { // Use global areas if interface specific not set, or if needed for L1 component of L1/L2
        area_tlv_value_content.areaAddresses = local_area_addresses_;
    }

    bool add_area_tlv_to_lan_l1 = (if_state.config.level == IsisLevel::L1 || if_state.config.level == IsisLevel::L1_L2) && !area_tlv_value_content.areaAddresses.empty();
    // For P2P, condition will be checked later based on circuitType.

    if (!area_tlv_value_content.areaAddresses.empty()) {
        area_tlv.type = AREA_ADDRESSES_TLV_TYPE;
        // Manual serialization as before, or use serialize_area_addresses_tlv_value if it exists and is preferred.
        for(const auto& area : area_tlv_value_content.areaAddresses) {
            area_tlv.value.push_back(static_cast<uint8_t>(area.size()));
            area_tlv.value.insert(area_tlv.value.end(), area.begin(), area.end());
        }
        area_tlv.length = static_cast<uint8_t>(area_tlv.value.size());
    }

    // --- Protocols Supported TLV (NLPID, Type 129) ---
    TLV protocols_tlv;
    protocols_tlv.type = PROTOCOLS_SUPPORTED_TLV_TYPE;
    protocols_tlv.value.push_back(0xCC); // NLPID for IP
    // protocols_tlv.value.push_back(0x8E); // NLPID for IPv6 if supported
    protocols_tlv.length = static_cast<uint8_t>(protocols_tlv.value.size());

    // --- IP Interface Address TLV (Type 132) ---
    TLV ip_interface_tlv;
    ip_interface_tlv.type = IP_INTERNAL_REACH_TLV_TYPE; // Actually 132 for IP Interface Address
                                                        // Using 128 (IP Internal Reach) is not standard for IIH interface addr
                                                        // Correct type for IP Intf Addr is 132
    ip_interface_tlv.type = 132; 
    // Value is the 4-byte IP address from source_ip_for_hello
    uint32_t ip_addr_net_hello = htonl(source_ip_for_hello); // Ensure network byte order if IpAddress is host order
    const uint8_t* ip_bytes_hello = reinterpret_cast<const uint8_t*>(&ip_addr_net_hello);
    ip_interface_tlv.value.insert(ip_interface_tlv.value.end(), ip_bytes_hello, ip_bytes_hello + 4);
    ip_interface_tlv.length = static_cast<uint8_t>(ip_interface_tlv.value.size());


    uint16_t holding_time = if_state.config.hello_interval_seconds * if_state.config.holding_timer_multiplier;

    // Based on circuit type
    if (if_state.config.circuit_type == CircuitType::BROADCAST) {
        LanHelloPdu lan_pdu;
        lan_pdu.commonHeader = common_header; // Base common header
        lan_pdu.sourceId = local_system_id_;
        lan_pdu.holdingTime = htons(holding_time);
        lan_pdu.priority = if_state.config.priority;
        
        // LAN ID: Current DIS SystemID (6 bytes) + Pseudonode ID (1 byte)
        // If we are DIS, use our own system ID + our chosen pseudonode ID.
        // if_state.actual_lan_id should be populated by perform_dis_election when is_dis is true.
        // If we are not DIS, use the elected DIS's LAN ID (if_state.current_dis_lan_id).
        // If no DIS elected yet, this might be zero or our own ID with a zero pseudonode.
        if (if_state.is_dis) {
            lan_pdu.lanId = if_state.actual_lan_id;
        } else {
            bool dis_lan_id_is_set = false;
            for(size_t i=0; i < 6; ++i) if(if_state.current_dis_lan_id[i] != 0) dis_lan_id_is_set = true;
            if(dis_lan_id_is_set) {
                lan_pdu.lanId = if_state.current_dis_lan_id;
            } else { // No DIS known, or current_dis_lan_id is zeroed
                 std::copy(local_system_id_.begin(), local_system_id_.end(), lan_pdu.lanId.begin());
                 lan_pdu.lanId[6] = 0; // Default pseudonode ID when no DIS or self not DIS
            }
        }
        
        // Area TLV for L1 LAN Hello
        if (add_area_tlv_to_lan_l1 && area_tlv.length > 0) {
             lan_pdu.tlvs.push_back(area_tlv);
        }
        lan_pdu.tlvs.push_back(protocols_tlv);
        lan_pdu.tlvs.push_back(ip_interface_tlv);

        // IS Neighbors TLV (Type 2 for LAN IIH) - list of 6-byte MAC addresses of UP neighbors
        TLV is_neighbors_lan_tlv;
        is_neighbors_lan_tlv.type = IS_NEIGHBORS_LAN_TLV_TYPE;
        for(const auto& adj_pair : if_state.adjacencies) {
            if (adj_pair.second.state == AdjacencyState::UP) {
                 // Add neighbor's MAC address (6 bytes)
                is_neighbors_lan_tlv.value.insert(is_neighbors_lan_tlv.value.end(), 
                                                  adj_pair.second.neighbor_mac_address.octets().begin(),
                                                  adj_pair.second.neighbor_mac_address.octets().end());
            }
        }
        if (!is_neighbors_lan_tlv.value.empty()) {
            is_neighbors_lan_tlv.length = static_cast<uint8_t>(is_neighbors_lan_tlv.value.size());
            lan_pdu.tlvs.push_back(is_neighbors_lan_tlv);
        }


        // Determine PDU type (L1, L2, or both)
        // Send L1 Hello
        if (if_state.config.level == IsisLevel::L1 || if_state.config.level == IsisLevel::L1_L2) {
            lan_pdu.commonHeader.pduType = L1_LAN_IIH_TYPE;
            lan_pdu.circuitType = (if_state.config.level == IsisLevel::L1_L2) ? 0x03 : 0x01;
            
            // Ensure Area TLV is present for L1/L1_L2, and other TLVs are correctly set for L1
            // If lan_pdu.tlvs was cleared or modified for L2, rebuild for L1 if necessary.
            // For simplicity, assume lan_pdu.tlvs is built once, then Area TLV conditionally removed for pure L2.
            // The current logic for add_area_tlv_to_lan_l1 handles its presence.

            std::vector<uint8_t> serialized_l1_pdu = serialize_lan_hello_pdu(lan_pdu);
            send_pdu_callback_(interface_id, ALL_L1_ISS_MAC, serialized_l1_pdu);
        }
        // Send L2 Hello
        if (if_state.config.level == IsisLevel::L2 || if_state.config.level == IsisLevel::L1_L2) {
            // Potentially re-use lan_pdu structure but modify for L2 specifics
            lan_pdu.commonHeader.pduType = L2_LAN_IIH_TYPE;
            lan_pdu.circuitType = (if_state.config.level == IsisLevel::L1_L2) ? 0x03 : 0x02;
            
            // L2 Hellos SHOULD NOT include Area Address TLV.
            // If it was added for L1 component of L1/L2, remove it now for L2 Hello.
            // If strictly L2, add_area_tlv_to_lan_l1 was false, so it wasn't added.
            if (if_state.config.level == IsisLevel::L1_L2 && add_area_tlv_to_lan_l1) { // Was L1/L2 and Area TLV was added for L1 part
                auto it_area = std::remove_if(lan_pdu.tlvs.begin(), lan_pdu.tlvs.end(),
                                            [](const TLV& t){ return t.type == AREA_ADDRESSES_TLV_TYPE; });
                if (it_area != lan_pdu.tlvs.end()) lan_pdu.tlvs.erase(it_area, lan_pdu.tlvs.end());
            } else if (if_state.config.level == IsisLevel::L2) { // Strictly L2
                 // Ensure area_tlv is not there (it shouldn't have been added if add_area_tlv_to_lan_l1 was false)
                auto it_area = std::remove_if(lan_pdu.tlvs.begin(), lan_pdu.tlvs.end(),
                                            [](const TLV& t){ return t.type == AREA_ADDRESSES_TLV_TYPE; });
                if (it_area != lan_pdu.tlvs.end()) lan_pdu.tlvs.erase(it_area, lan_pdu.tlvs.end());
            }


            std::vector<uint8_t> serialized_l2_pdu = serialize_lan_hello_pdu(lan_pdu);
            send_pdu_callback_(interface_id, ALL_L2_ISS_MAC, serialized_l2_pdu);
        }

    } else { // P2P
        PointToPointHelloPdu ptp_pdu;
        ptp_pdu.commonHeader = common_header;
        ptp_pdu.commonHeader.pduType = PTP_IIH_TYPE; // 0x11
        // Circuit type for PTP IIH indicates L1/L2 capability of sender on this circuit
        if (if_state.config.level == IsisLevel::L1) ptp_pdu.circuitType = 0x01;
        else if (if_state.config.level == IsisLevel::L2) ptp_pdu.circuitType = 0x02;
        else if (if_state.config.level == IsisLevel::L1_L2) ptp_pdu.circuitType = 0x03; // L1 and L2 capable
        else ptp_pdu.circuitType = 0x00; // Should not happen if ISIS is enabled


        ptp_pdu.sourceId = local_system_id_;
        ptp_pdu.holdingTime = htons(holding_time);
        ptp_pdu.localCircuitId = static_cast<uint8_t>(interface_id & 0xFF); // Example, should be unique per P2P link on system

        // Area Address TLV for P2P Hellos: only if L1 or L1/L2 capable (circuitType 0x01 or 0x03)
        if ((ptp_pdu.circuitType == 0x01 || ptp_pdu.circuitType == 0x03) && area_tlv.length > 0) {
             ptp_pdu.tlvs.push_back(area_tlv);
        }
        ptp_pdu.tlvs.push_back(protocols_tlv);
        ptp_pdu.tlvs.push_back(ip_interface_tlv);

        // P2P Adjacency State TLV (Type 240)
        TLV p2p_adj_tlv;
        p2p_adj_tlv.type = P2P_ADJACENCY_STATE_TLV_TYPE;
        uint32_t local_elcid = htonl(interface_id); // Use interface_id for ELCID, ensure uniqueness

        if (if_state.adjacencies.empty()) { // No adjacency yet
            p2p_adj_tlv.value.push_back(0x01); // Adjacency State: Down
            const uint8_t* elc_bytes = reinterpret_cast<const uint8_t*>(&local_elcid);
            p2p_adj_tlv.value.insert(p2p_adj_tlv.value.end(), elc_bytes, elc_bytes + 4);
        } else {
            const IsisAdjacency& first_adj = if_state.adjacencies.begin()->second; // Assuming one primary adjacency for P2P
            if (first_adj.state == AdjacencyState::UP) p2p_adj_tlv.value.push_back(0x03); // Up
            else if (first_adj.state == AdjacencyState::INITIALIZING) p2p_adj_tlv.value.push_back(0x02); // Initializing
            else p2p_adj_tlv.value.push_back(0x01); // Down
            
            const uint8_t* elc_bytes = reinterpret_cast<const uint8_t*>(&local_elcid);
            p2p_adj_tlv.value.insert(p2p_adj_tlv.value.end(), elc_bytes, elc_bytes + 4);

            if ((first_adj.state == AdjacencyState::INITIALIZING || first_adj.state == AdjacencyState::UP) && first_adj.neighbor_elcid_known) {
                p2p_adj_tlv.value.insert(p2p_adj_tlv.value.end(), first_adj.neighbor_system_id.begin(), first_adj.neighbor_system_id.end());
                uint32_t neighbor_elcid_net = htonl(first_adj.neighbor_extended_local_circuit_id);
                const uint8_t* neighbor_elc_bytes = reinterpret_cast<const uint8_t*>(&neighbor_elcid_net);
                p2p_adj_tlv.value.insert(p2p_adj_tlv.value.end(), neighbor_elc_bytes, neighbor_elc_bytes + 4);
            }
        }
        p2p_adj_tlv.length = static_cast<uint8_t>(p2p_adj_tlv.value.size());
        if (p2p_adj_tlv.length > 0) ptp_pdu.tlvs.push_back(p2p_adj_tlv);
        
        std::vector<uint8_t> serialized_pdu = serialize_point_to_point_hello_pdu(ptp_pdu);
        
        MacAddress dest_mac;
        bool p2p_dest_mac_is_unicast = !if_state.config.p2p_destination_mac.is_zero() &&
                                       !(if_state.config.p2p_destination_mac.octets()[0] & 0x01); // Basic multicast check

        if (p2p_dest_mac_is_unicast) {
            dest_mac = if_state.config.p2p_destination_mac;
        } else {
            if (if_state.config.level == IsisLevel::L1) dest_mac = ALL_L1_ISS_MAC;
            else if (if_state.config.level == IsisLevel::L2) dest_mac = ALL_L2_ISS_MAC;
            else if (if_state.config.level == IsisLevel::L1_L2) {
                 // For L1/L2 P2P, send PTP IIH with circuitType 0x03 (L1/L2 capable)
                 // Standard practice is to send to AllL1ISs or AllP2PISs.
                 // Sending two separate Hellos (one L1, one L2) is also an option but more complex.
                 // Here, we send one L1/L2 PTP IIH. Choosing ALL_L1_ISS_MAC or ALL_L2_ISS_MAC.
                 // Or a generic AllP2PISs if available. For now, stick to L1/L2 specific.
                 dest_mac = ALL_L1_ISS_MAC; // Or ALL_L2_ISS_MAC, or alternate based on actual PDU content level if sending two.
                                          // Since ptp_pdu.circuitType is 0x03, it's an L1/L2 Hello.
            } else {
                 dest_mac = ALL_L1_ISS_MAC; // Fallback, though circuitType would be 0x00 (None)
            }
        }
        send_pdu_callback_(interface_id, dest_mac, serialized_pdu);
    }
}

void IsisInterfaceManager::check_adjacency_timeouts(uint32_t interface_id, IsisInterfaceState& if_state) {
    auto now = std::chrono::steady_clock::now();
    bool dis_election_needed = false;

    for (auto adj_it = if_state.adjacencies.begin(); adj_it != if_state.adjacencies.end(); /* manual increment */) {
        IsisAdjacency& adj = adj_it->second;
        if (adj.state != AdjacencyState::DOWN) {
            if (now > adj.last_hello_received_time + std::chrono::seconds(adj.holding_time_seconds)) {
                // std::cout << "Adjacency timeout for " << system_id_to_string(adj.neighbor_system_id) 
                //           << " on interface " << interface_id << std::endl;
                update_adjacency_state(adj, AdjacencyState::DOWN, if_state.config.circuit_type == CircuitType::BROADCAST);
                if (if_state.config.circuit_type == CircuitType::BROADCAST) {
                    dis_election_needed = true; // Lost an adjacency, DIS might change
                }
                adj_it = if_state.adjacencies.erase(adj_it); // Remove timed-out adjacency
                continue;
            }
        }
        ++adj_it;
    }
    if (dis_election_needed) {
        perform_dis_election(interface_id, if_state);
    }
}

void IsisInterfaceManager::perform_dis_election(uint32_t interface_id, IsisInterfaceState& if_state) {
    if (if_state.config.circuit_type != CircuitType::BROADCAST) return;

    SystemID elected_dis_system_id{};
    uint8_t highest_priority = 0;
    MacAddress mac_for_tie_break{}; // Highest MAC for tie-breaking priority
    bool first_candidate = true;
    bool current_router_is_dis = false;

    // Consider self for DIS election
    highest_priority = if_state.config.priority;
    auto self_if_config_opt = underlying_interface_manager_.get_port_config(interface_id);
    if (self_if_config_opt) { // Check if config exists
        mac_for_tie_break = self_if_config_opt->mac_address; // Directly use mac_address from PortConfig
    } else {
        // Cannot be DIS without a MAC address for tie-breaking if needed.
        // This is an issue, should have MAC. For now, use zero MAC, will lose tie.
        mac_for_tie_break = MacAddress("00:00:00:00:00:00");
    }
    elected_dis_system_id = local_system_id_;
    current_router_is_dis = true; // Assume self is DIS initially

    // Iterate through UP adjacencies
    for (const auto& adj_pair : if_state.adjacencies) {
        const IsisAdjacency& adj = adj_pair.second;
        if (adj.state == AdjacencyState::UP) {
            if (adj.neighbor_priority > highest_priority) {
                highest_priority = adj.neighbor_priority;
                mac_for_tie_break = adj.neighbor_mac_address;
                elected_dis_system_id = adj.neighbor_system_id;
                current_router_is_dis = false;
            } else if (adj.neighbor_priority == highest_priority) {
                // Tie-break with MAC address (higher MAC wins)
                if (adj.neighbor_mac_address.to_uint64() > mac_for_tie_break.to_uint64()) {
                     mac_for_tie_break = adj.neighbor_mac_address;
                     elected_dis_system_id = adj.neighbor_system_id;
                     current_router_is_dis = false;
                } else if (adj.neighbor_mac_address.to_uint64() == mac_for_tie_break.to_uint64()) {
                    // Extremely unlikely, but standard mentions SystemID as final tie-breaker
                    // Convert SystemID to a comparable form (e.g. uint64_t or lexicographical)
                    // For simplicity: lexicographical compare
                    if (adj.neighbor_system_id > elected_dis_system_id) { // Assuming std::array operator> works as needed
                        elected_dis_system_id = adj.neighbor_system_id;
                        current_router_is_dis = false;
                    }
                }
            }
        }
    }
    
    bool old_dis_status = if_state.is_dis;
    if_state.is_dis = current_router_is_dis;

    // Update current_dis_lan_id (SystemID of DIS + Pseudonode ID)
    // Pseudonode ID is chosen by the DIS. Often 1, or interface index.
    // For simplicity, if we are DIS, use pseudonode 1.
    // If another is DIS, we learn their pseudonode ID from their Hellos (adj.neighbor_learned_lan_id).
    std::fill(if_state.current_dis_lan_id.begin(), if_state.current_dis_lan_id.end(), 0);
    std::copy(elected_dis_system_id.begin(), elected_dis_system_id.end(), if_state.current_dis_lan_id.begin());

    if (current_router_is_dis) {
        if_state.current_dis_lan_id[6] = static_cast<uint8_t>(interface_id & 0xFF); // Our chosen pseudonode ID
        if_state.actual_lan_id = if_state.current_dis_lan_id; // Store our LAN ID
        // std::cout << "Interface " << interface_id << ": This router is DIS." << std::endl;
    } else {
        // Find the adjacency for the elected DIS to get their pseudonode ID
        auto dis_adj_it = if_state.adjacencies.find(elected_dis_system_id);
        if (dis_adj_it != if_state.adjacencies.end() && dis_adj_it->second.neighbor_learned_lan_id.has_value()) {
            // Ensure the learned LAN ID's SystemID part matches the elected_dis_system_id
            bool learned_lan_id_matches_dis = true;
            for(size_t i=0; i<6; ++i) {
                if (dis_adj_it->second.neighbor_learned_lan_id.value()[i] != elected_dis_system_id[i]) {
                    learned_lan_id_matches_dis = false;
                    break;
                }
            }
            if (learned_lan_id_matches_dis) {
                 if_state.current_dis_lan_id[6] = dis_adj_it->second.neighbor_learned_lan_id.value()[6]; // Use pseudonode from DIS's Hello
            } else {
                 // This case should ideally not happen if data is consistent.
                 // DIS's Hello should have its own SystemID in the LAN ID.
                 if_state.current_dis_lan_id[6] = 0; // Mismatch, treat pseudonode as unknown
            }
        } else {
            if_state.current_dis_lan_id[6] = 0; // Unknown pseudonode ID if DIS not adjacent or LAN ID not in Hello
        }
        // std::cout << "Interface " << interface_id << ": Router " << system_id_to_string(elected_dis_system_id) << " is DIS." << std::endl;
    }
    
    if (old_dis_status != if_state.is_dis) {
        // std::cout << "DIS status changed on interface " << interface_id << ". New DIS: " << (if_state.is_dis ? "self" : system_id_to_string(elected_dis_system_id)) << std::endl;
        // TODO: Signal DIS status change to the main IS-IS Manager.
        // This is important because a change in DIS status (gaining or losing DIS role)
        // requires the router to regenerate its own LSPs to add/remove pseudonode TLVs
        // and potentially adjust adjacencies advertised.
    }
}


std::optional<IpAddress> IsisInterfaceManager::extract_ip_address_from_tlvs(const std::vector<TLV>& tlvs) const {
    for (const auto& tlv : tlvs) {
        if (tlv.type == 132 && tlv.length >= 4) { // IP Interface Address TLV
            uint32_t ip_val_net;
            std::memcpy(&ip_val_net, tlv.value.data(), 4);
            return IpAddress(ntohl(ip_val_net)); // Assuming IpAddress has constructor from uint32_t (host order)
        }
    }
    return std::nullopt;
}

bool IsisInterfaceManager::check_area_match(const AreaAddress& local_area, const std::vector<TLV>& tlvs) const {
    if (local_area.empty()) return true; // If local area not defined, don't check (matches L2, or L1 if neighbor also has no area TLV)

    for (const auto& tlv : tlvs) {
        if (tlv.type == AREA_ADDRESSES_TLV_TYPE) {
            AreaAddressesTlvValue area_val;
            // This parse function needs to be available from isis_pdu.cpp
            // if (parse_area_addresses_tlv_value(tlv.value, area_val)) {
            // Manual parsing for now:
            BufferReader reader(tlv.value.data(), tlv.value.size());
            while(reader.offset < reader.size_) { // Fixed .size to .size_
                uint8_t current_area_len;
                if (!parse_u8(reader, current_area_len)) break;
                if (!reader.can_read(current_area_len)) break;
                AreaAddress current_area(current_area_len);
                if(!parse_bytes(reader, current_area.data(), current_area_len)) break;
                
                if (current_area == local_area) {
                    return true;
                }
            }
            return false; // Area TLV present, but no match
        }
    }
    // No Area Address TLV found in Hello.
    // For L1, this means an area mismatch unless our local_area is also empty (which is unlikely for L1).
    // Standard says L1 IIH MUST contain Area Address TLV. If it's missing, it's a malformed L1 Hello.
    return false; 
}


bool IsisInterfaceManager::check_p2p_adjacency_three_way_state(const PointToPointHelloPdu& received_hello, const IsisInterfaceState& if_state) const {
    // Find P2P Adjacency State TLV (Type 240)
    for (const auto& tlv : received_hello.tlvs) {
        if (tlv.type == P2P_ADJACENCY_STATE_TLV_TYPE && tlv.length >= 5) { // Min length for state + Local Circuit ID
            uint8_t neighbor_reported_adj_state = tlv.value[0];
            // uint32_t neighbor_local_circuit_id; // Their Local Circuit ID
            // memcpy(&neighbor_local_circuit_id, tlv.value.data() + 1, 4);
            // neighbor_local_circuit_id = ntohl(neighbor_local_circuit_id);

            // We need to check if they are reporting us as a neighbor (Neighbor System ID field in TLV)
            // And if their Adjacency State for us is INITIALIZING or UP.
            if (tlv.length >= 11) { // State (1) + LocalCID (4) + NeighborSysID (6)
                 SystemID reported_neighbor_of_neighbor;
                 std::copy(tlv.value.begin() + 5, tlv.value.begin() + 11, reported_neighbor_of_neighbor.begin());
                 if (reported_neighbor_of_neighbor != local_system_id_) {
                     return false; // They are talking about someone else or no one
                 }
            } else {
                return false; // TLV too short to confirm they see us
            }


            // If neighbor_reported_adj_state is UP (0x03) or INITIALIZING (0x02), it's a match for us to go UP.
            if (neighbor_reported_adj_state == 0x03 || neighbor_reported_adj_state == 0x02) {
                return true;
            }
        }
    }
    return false; // No P2P Adjacency TLV or state not conducive to coming UP.
}


} // namespace isis
} // namespace netflow

// Define P2P_ADJACENCY_STATE_TLV_TYPE if not globally available
// This should ideally be in a common constants header (e.g. isis_pdu_constants.hpp or in isis_common.hpp)
#ifndef P2P_ADJACENCY_STATE_TLV_TYPE
#define P2P_ADJACENCY_STATE_TLV_TYPE 240
#endif

#ifndef IS_NEIGHBORS_LAN_TLV_TYPE // Already in isis_common.hpp
#define IS_NEIGHBORS_LAN_TLV_TYPE 2
#endif

#ifndef AREA_ADDRESSES_TLV_TYPE // Already in isis_common.hpp
#define AREA_ADDRESSES_TLV_TYPE 1
#endif

#ifndef PROTOCOLS_SUPPORTED_TLV_TYPE // Already in isis_common.hpp
#define PROTOCOLS_SUPPORTED_TLV_TYPE 129
#endif

// IP Interface Address TLV type (standard is 132)
#ifndef IP_INTERFACE_ADDRESS_TLV_TYPE
#define IP_INTERFACE_ADDRESS_TLV_TYPE 132
#endif

// Note: parse_area_addresses_tlv_value and parse_is_neighbors_tlv_value are assumed to be
// available from isis_pdu.cpp or a similar PDU parsing utility library.
// For this implementation, small local parsers or direct byte access is used.

// The definition of IsisInterfaceManager::get_dis_mac_address will be kept (or moved if it was global).
// Assuming the global one at the end of the file was the one to be corrected and used as the class method.
// The previous turn's output shows it's already correctly scoped as a class member.
// The issue was that the compiler was seeing a global one due to a previous error state of the file.
// If it's indeed correctly defined within the class scope now, this search block won't find a global one to remove.
// If there was a *separate* global definition, this would remove it.
// For now, this change assumes there isn't a *duplicate* global definition to remove,
// as the one at the end of the file in previous listings was ALREADY scoped with IsisInterfaceManager::
// This means the error was likely due to a parsing issue by the compiler with the includes/macros or a previous bad state.
// Let's confirm the existing definition is correctly scoped and not global.
// The file content provided in Turn 26 shows `std::optional<MacAddress> IsisInterfaceManager::get_dis_mac_address(...)`
// which is a correctly scoped definition, not a global one.
// Therefore, the error "‘MacAddress’ was not declared in this scope" for a global function points to
// an include issue for that specific (erroneous) global definition, or the compiler getting confused.
// The actual fix is to ensure ONLY the class member definition exists and is used.
// No change needed here if the global one doesn't exist / was a misinterpretation of compiler errors from an old state.
// The provided file content shows it's already a class member.
// The specific errors like "‘MacAddress’ was not declared in this scope" for `get_dis_mac_address`
// usually happen if the function signature is outside the class/namespace and types like `MacAddress` aren't visible there.
// Since the function IS defined as `IsisInterfaceManager::get_dis_mac_address`, the types *should* be visible if includes are correct.
// The error `‘IsisInterfaceManager’ has not been declared` for that function implies the definition itself was somehow misplaced by the tool or in a bad state.

// To be safe, ensuring no *additional* global definition exists:
// If a truly global `std::optional<MacAddress> get_dis_mac_address(...)` existed, it would be removed.
// But based on current file, it's already a member.
// The problem might be the `#define`s at the end of the file.
// Let's remove the `#define`s for TLV types at the end of the .cpp file as they should be in headers.
