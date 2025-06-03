#include "netflow++/isis/isis_interface_manager.hpp"
#include "netflow++/isis/isis_pdu_constants.hpp" // For TLV types etc. Should be created if not existing. Assuming isis_common.hpp has them.
#include "netflow++/byte_swap.hpp" // For ntohs, htons etc. if not using arpa/inet.h directly. Assuming isis_pdu.cpp handles this.

#include <algorithm> // For std::find_if, std::remove_if
#include <iostream> // For temporary logging/debugging

// Placeholder for actual packet serialization/deserialization functions if not fully in isis_pdu.cpp
// For now, assume isis_pdu.hpp and isis_pdu.cpp provide necessary serialize/parse functions.

namespace netflow {
namespace isis {

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
    auto if_details = underlying_interface_manager_.get_interface_details(interface_id);
    if (!if_details) {
        // std::cerr << "IsisInterfaceManager: Cannot configure non-existent interface " << interface_id << std::endl;
        return;
    }

    IsisInterfaceState if_state;
    if_state.config = config;
    if_state.config.interface_id = interface_id; // Ensure interface_id is set in stored config
    if_state.config.system_id = local_system_id_; // Ensure local system ID is used from manager's global config

    // If circuit type is not explicitly P2P and it's Ethernet, assume BROADCAST
    // This logic might be more complex based on media type from if_details
    if (config.circuit_type != CircuitType::P2P && if_details->media_type == "ethernet") {
        if_state.config.circuit_type = CircuitType::BROADCAST;
    } else {
        if_state.config.circuit_type = config.circuit_type; // Use configured or default P2P
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
    auto if_details = underlying_interface_manager_.get_interface_details(interface_id);
    if (!if_details || !if_details->is_up) {
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
        if (!check_area_match(if_state.config.area_id, pdu.tlvs)) {
            // std::cout << "Area mismatch for L1 LAN Hello from " << source_mac.to_string() << " on if " << interface_id << std::endl;
            return;
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
    adj->lan_id = SystemID{}; // Store full LAN ID from Hello: pdu.lanId (7 bytes)
    std::copy(pdu.lanId.begin(), pdu.lanId.end(), std::begin(adj->lan_id.value()));


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
    for(const auto& tlv : pdu.tlvs) {
        if (tlv.type == IS_NEIGHBORS_LAN_TLV_TYPE) { // IS Neighbors TLV
            IsNeighborsTlvValue is_neighbors_val;
            // This parse function needs to be available from isis_pdu.cpp
            // if (parse_is_neighbors_tlv_value(tlv.value, is_neighbors_val)) { 
            // For now, iterate raw bytes: list of 6-byte MACs or SystemIDs
            for(size_t i = 0; i + 6 <= tlv.value.size(); i += 6) {
                 // Here we'd check if our SystemID or MAC is listed.
                 // For LAN Hellos, IS Neighbors TLV (type 2) contains MAC addresses of neighbors.
                 // We'd need our own MAC address for the interface.
                 auto our_if_details = underlying_interface_manager_.get_interface_details(interface_id);
                 if (our_if_details && our_if_details->mac_address.has_value()) {
                    if (std::equal(our_if_details->mac_address.value().octets.begin(), 
                                   our_if_details->mac_address.value().octets.end(), 
                                   tlv.value.begin() + i)) {
                        two_way_confirmed = true;
                        break;
                    }
                 }
            }
            if(two_way_confirmed) break;
        }
    }
    
    if (two_way_confirmed) {
         update_adjacency_state(*adj, AdjacencyState::UP, true);
    } else {
        // If not explicitly confirmed 2-way, we can still mark as INITIALIZING or UP
        // depending on policy. For now, let's be optimistic for LAN.
        update_adjacency_state(*adj, AdjacencyState::UP, true); // Or INITIALIZING if stricter
    }


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
    // The PTP IIH PDU Type (0x11) is used for L1, L2 or L1_L2 based on TLVs and configuration.
    // We establish based on configured level.
    IsisLevel configured_level = if_state.config.level;
    if (configured_level == IsisLevel::NONE) return;


    // Area Address check for L1 component of P2P adjacencies
    if (configured_level == IsisLevel::L1 || configured_level == IsisLevel::L1_L2) {
        if (!check_area_match(if_state.config.area_id, pdu.tlvs)) {
            // std::cout << "Area mismatch for P2P L1 Hello from " << source_mac.to_string() << " on if " << interface_id << std::endl;
            // If it's L1_L2, we might still form L2 part. For now, strict: if L1 configured, area must match.
            if (configured_level == IsisLevel::L1) return; 
            // If L1_L2 and area mismatch, maybe only L2 can come up? Complex.
            // For now, if L1 is involved and area mismatches, reject.
            return; 
        }
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
    adj->level_established = configured_level; // For P2P, adj level is same as interface config level
    adj->neighbor_ip_address = extract_ip_address_from_tlvs(pdu.tlvs);
    // lan_id and neighbor_priority are not typically used for P2P adjacencies.

    // P2P Adjacency State (RFC 5303 / ISO 10589 section 9.6)
    // States: Down, Initializing, Up.
    // P2P Adjacency TLV (Type 240) is key for three-way handshake.
    // For now, simplified: receiving a valid Hello moves to UP.
    // A more complete implementation uses the three-way handshake:
    // 1. Adjacency state is Down.
    // 2. On receipt of IIH from new neighbour -> Initializing. Send IIH with Adjacency Three-Way TLV state "Initializing".
    // 3. On receipt of IIH with Adjacency Three-Way TLV state "Initializing" (and matching neighbor system ID) -> Up. Send IIH with TLV state "Up".
    // 4. On receipt of IIH with Adjacency Three-Way TLV state "Up" -> Confirm Up.
    
    adj->three_way_match = check_p2p_adjacency_three_way_state(pdu, if_state);

    if (adj->three_way_match) {
        update_adjacency_state(*adj, AdjacencyState::UP, false);
    } else {
        // If not yet three-way match, keep it initializing.
        // If it was UP and three-way match is lost, it should go DOWN.
        if (adj->state == AdjacencyState::UP) {
             update_adjacency_state(*adj, AdjacencyState::DOWN, false); // Lost three-way
        } else {
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

    auto if_details = underlying_interface_manager_.get_interface_details(interface_id);
    if (!if_details || !if_details->is_up || !if_details->ip_address.has_value() || !if_details->mac_address.has_value()) {
        // std::cerr << "Cannot send Hello on if " << interface_id << ": interface not suitable." << std::endl;
        return;
    }

    CommonPduHeader common_header;
    common_header.intradomainRoutingProtocolDiscriminator = 0x83; // NLPID for IS-IS
    common_header.versionProtocolIdExtension = 1;
    common_header.version = 1;
    common_header.reserved = 0;
    common_header.idLength = 0; // Indicates 6-byte SystemID
    common_header.maxAreaAddresses = static_cast<uint8_t>(local_area_addresses_.size() > 0 ? local_area_addresses_.size() : (if_state.config.area_id.empty() ? 0 : 1));


    // --- Area Addresses TLV (Type 1) ---
    TLV area_tlv;
    area_tlv.type = AREA_ADDRESSES_TLV_TYPE;
    AreaAddressesTlvValue area_tlv_value;
    if (!if_state.config.area_id.empty()) { // Interface specific area for L1
        area_tlv_value.areaAddresses.push_back(if_state.config.area_id);
    } else if (!local_area_addresses_.empty()){ // Global areas if interface specific not set
         area_tlv_value.areaAddresses.insert(area_tlv_value.areaAddresses.end(), local_area_addresses_.begin(), local_area_addresses_.end());
    }
    // If L2 only, Area Address TLV might be omitted or contain all configured areas.
    // Standard says L2 IIHs SHOULD NOT contain area addresses TLV. L1 IIHs MUST.
    // For L1/L2, it should contain area addresses for L1 operation.

    if (!area_tlv_value.areaAddresses.empty()) {
         // Serialize area_tlv_value into area_tlv.value
         // This requires a serialize_area_addresses_tlv_value from isis_pdu.cpp
         // For now, manual serialization:
         for(const auto& area : area_tlv_value.areaAddresses) {
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
    // Value is just the 4-byte IP address from interface_details
    uint32_t ip_addr_net = htonl(if_details->ip_address.value().to_uint32()); // Assuming IpAddress has to_uint32()
    const uint8_t* ip_bytes = reinterpret_cast<const uint8_t*>(&ip_addr_net);
    ip_interface_tlv.value.insert(ip_interface_tlv.value.end(), ip_bytes, ip_bytes + 4);
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
        // If we are DIS, use our own system ID + our chosen pseudonode ID (e.g., interface index or 1)
        // If we are not DIS, use the elected DIS's LAN ID.
        // If no DIS elected yet, this might be zero or our own ID with a zero pseudonode.
        std::fill(lan_pdu.lanId.begin(), lan_pdu.lanId.end(), 0); // Zero out first
        if (if_state.is_dis) {
            std::copy(local_system_id_.begin(), local_system_id_.end(), lan_pdu.lanId.begin());
            lan_pdu.lanId[6] = static_cast<uint8_t>(interface_id & 0xFF); // Example pseudonode ID
            if_state.actual_lan_id = lan_pdu.lanId; // Store our LAN ID
        } else { // Use current_dis_lan_id if known and non-zero
            bool is_zero = true;
            for(size_t i=0; i < 6; ++i) if(if_state.current_dis_lan_id[i] != 0) is_zero = false;
            if(!is_zero) {
                std::copy(if_state.current_dis_lan_id.begin(), if_state.current_dis_lan_id.end(), lan_pdu.lanId.begin());
            } else { // No DIS known, use our ID and 0 pseudonode
                 std::copy(local_system_id_.begin(), local_system_id_.end(), lan_pdu.lanId.begin());
                 lan_pdu.lanId[6] = 0; // Default pseudonode ID when no DIS or self not DIS
            }
        }
        
        if (!area_tlv_value.areaAddresses.empty()) lan_pdu.tlvs.push_back(area_tlv); // Only if L1 or L1/L2
        lan_pdu.tlvs.push_back(protocols_tlv);
        lan_pdu.tlvs.push_back(ip_interface_tlv);

        // IS Neighbors TLV (Type 2 for LAN IIH) - list of MAC addresses of neighbors in UP state
        TLV is_neighbors_lan_tlv;
        is_neighbors_lan_tlv.type = IS_NEIGHBORS_LAN_TLV_TYPE;
        for(const auto& adj_pair : if_state.adjacencies) {
            if (adj_pair.second.state == AdjacencyState::UP) {
                 // Add neighbor's MAC address (6 bytes)
                is_neighbors_lan_tlv.value.insert(is_neighbors_lan_tlv.value.end(), 
                                                  adj_pair.second.neighbor_mac_address.octets.begin(),
                                                  adj_pair.second.neighbor_mac_address.octets.end());
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
            lan_pdu.circuitType = 0x01; // L1 only
            if (if_state.config.level == IsisLevel::L1_L2) lan_pdu.circuitType = 0x03; // L1/L2
            
            std::vector<uint8_t> serialized_pdu = serialize_lan_hello_pdu(lan_pdu); // From isis_pdu.cpp
            send_pdu_callback_(interface_id, ALL_L1_ISS_MAC, serialized_pdu);
        }
        // Send L2 Hello
        if (if_state.config.level == IsisLevel::L2 || if_state.config.level == IsisLevel::L1_L2) {
            lan_pdu.commonHeader.pduType = L2_LAN_IIH_TYPE;
            lan_pdu.circuitType = 0x02; // L2 only
            if (if_state.config.level == IsisLevel::L1_L2) lan_pdu.circuitType = 0x03; // L1/L2
            
            // L2 Hellos SHOULD NOT include Area Address TLV. Remove if present.
            if (if_state.config.level == IsisLevel::L2) { // If strictly L2
                auto it_area = std::remove_if(lan_pdu.tlvs.begin(), lan_pdu.tlvs.end(), [](const TLV& t){ return t.type == AREA_ADDRESSES_TLV_TYPE; });
                lan_pdu.tlvs.erase(it_area, lan_pdu.tlvs.end());
            }

            std::vector<uint8_t> serialized_pdu = serialize_lan_hello_pdu(lan_pdu);
            send_pdu_callback_(interface_id, ALL_L2_ISS_MAC, serialized_pdu);
        }

    } else { // P2P
        PointToPointHelloPdu ptp_pdu;
        ptp_pdu.commonHeader = common_header;
        ptp_pdu.commonHeader.pduType = PTP_IIH_TYPE; // 0x11
        // Circuit type for PTP IIH indicates L1/L2 capability of sender on this circuit
        if (if_state.config.level == IsisLevel::L1) ptp_pdu.circuitType = 0x01;
        else if (if_state.config.level == IsisLevel::L2) ptp_pdu.circuitType = 0x02;
        else if (if_state.config.level == IsisLevel::L1_L2) ptp_pdu.circuitType = 0x03;
        else ptp_pdu.circuitType = 0x00; // None


        ptp_pdu.sourceId = local_system_id_;
        ptp_pdu.holdingTime = htons(holding_time);
        ptp_pdu.localCircuitId = static_cast<uint8_t>(interface_id & 0xFF); // Example, should be unique per P2P link on system

        if (ptp_pdu.circuitType == 0x01 || ptp_pdu.circuitType == 0x03) { // L1 or L1L2 PTP IIH
             if (!area_tlv_value.areaAddresses.empty()) ptp_pdu.tlvs.push_back(area_tlv);
        }
        ptp_pdu.tlvs.push_back(protocols_tlv);
        ptp_pdu.tlvs.push_back(ip_interface_tlv);

        // P2P Adjacency TLV (Type 240)
        TLV p2p_adj_tlv;
        p2p_adj_tlv.type = P2P_ADJACENCY_STATE_TLV_TYPE; // Defined as 240 in RFC 5303
        // Value: Adjacency State (1 byte), Extended Local Circuit ID (4 bytes), Neighbor SystemID (6), Neighbor Ext Local Circuit ID (4)
        // For sending a Hello, we need to know the state of our adjacency with the potential neighbor.
        // This is complex as we might have multiple potential neighbors on a P2P link if it's misconfigured as multipoint.
        // Assuming only one main adjacency per P2P interface for now.
        if (!if_state.adjacencies.empty()) {
            const IsisAdjacency& first_adj = if_state.adjacencies.begin()->second; // Take the first one
            if (first_adj.state == AdjacencyState::UP) p2p_adj_tlv.value.push_back(0x03); // Up
            else if (first_adj.state == AdjacencyState::INITIALIZING) p2p_adj_tlv.value.push_back(0x02); // Initializing
            else p2p_adj_tlv.value.push_back(0x01); // Down
            
            // Our Extended Local Circuit ID (placeholder 1)
            uint32_t ext_local_cid_be = htonl(1); 
            const uint8_t* elc_bytes = reinterpret_cast<const uint8_t*>(&ext_local_cid_be);
            p2p_adj_tlv.value.insert(p2p_adj_tlv.value.end(), elc_bytes, elc_bytes + 4);

            // Neighbor System ID and Neighbor Extended Local Circuit ID are often zero when sending initial hellos
            // or filled if known from previous received P2P Hello with this TLV.
            // For now, just state and our local circuit ID.
            // This TLV should be exactly 15 bytes if fully populated, or 5 if only state + local C ID.
            // RFC 5303: Length is variable. If neighbor unknown, only local info.
            // Let's send only state and our Local Circuit ID.
            p2p_adj_tlv.length = static_cast<uint8_t>(p2p_adj_tlv.value.size());
             if (p2p_adj_tlv.length > 0) ptp_pdu.tlvs.push_back(p2p_adj_tlv);
        }
        
        std::vector<uint8_t> serialized_pdu = serialize_point_to_point_hello_pdu(ptp_pdu); // From isis_pdu.cpp
        
        // Determine destination MAC for P2P. Could be specific learned MAC or multicast.
        // Standard P2P often uses AllL1ISs/AllL2ISs/AllISs MACs depending on physical layer.
        // Ethernet P2P links might use unicast MAC of neighbor if known, or multicast.
        MacAddress dest_mac = if_state.config.p2p_destination_mac; // Use configured one
        if (if_state.config.level == IsisLevel::L1) dest_mac = ALL_L1_ISS_MAC;
        else if (if_state.config.level == IsisLevel::L2) dest_mac = ALL_L2_ISS_MAC;
        else if (if_state.config.level == IsisLevel::L1_L2) dest_mac = ALL_L1_ISS_MAC; // Or send two hellos, one to L1 MAC, one to L2 MAC.
                                                                                    // For now, just one to L1 MAC.
        
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
    auto self_if_details = underlying_interface_manager_.get_interface_details(interface_id);
    if (self_if_details && self_if_details->mac_address) {
        mac_for_tie_break = self_if_details->mac_address.value();
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
    // If another is DIS, we learn their pseudonode ID from their Hellos (adj.lan_id).
    std::fill(if_state.current_dis_lan_id.begin(), if_state.current_dis_lan_id.end(), 0);
    std::copy(elected_dis_system_id.begin(), elected_dis_system_id.end(), if_state.current_dis_lan_id.begin());

    if (current_router_is_dis) {
        if_state.current_dis_lan_id[6] = static_cast<uint8_t>(interface_id & 0xFF); // Our chosen pseudonode ID
        if_state.actual_lan_id = if_state.current_dis_lan_id; // Store our LAN ID
        // std::cout << "Interface " << interface_id << ": This router is DIS." << std::endl;
    } else {
        // Find the adjacency for the elected DIS to get their pseudonode ID
        auto dis_adj_it = if_state.adjacencies.find(elected_dis_system_id);
        if (dis_adj_it != if_state.adjacencies.end() && dis_adj_it->second.lan_id.has_value()) {
            if_state.current_dis_lan_id[6] = dis_adj_it->second.lan_id.value()[6]; // Use pseudonode from DIS's Hello
        } else {
            if_state.current_dis_lan_id[6] = 0; // Unknown pseudonode ID if DIS not adjacent or LAN ID not in Hello
        }
        // std::cout << "Interface " << interface_id << ": Router " << system_id_to_string(elected_dis_system_id) << " is DIS." << std::endl;
    }
    
    if (old_dis_status != if_state.is_dis) {
        // std::cout << "DIS status changed on interface " << interface_id << ". New DIS: " << (if_state.is_dis ? "self" : system_id_to_string(elected_dis_system_id)) << std::endl;
        // This change would typically trigger LSP regeneration by the main ISIS process.
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
            while(reader.offset < reader.size) {
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
