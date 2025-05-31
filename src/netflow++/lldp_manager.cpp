#include "netflow++/lldp_manager.hpp"
#include "netflow++/packet.hpp" // For MacAddress, and Packet structure if used directly
#include "netflow++/interface_manager.hpp" // For InterfaceManager methods

#include <arpa/inet.h> // For htons, ntohs
#include <algorithm>   // For std::find_if, std::remove_if
#include <iostream>    // For debugging (temporary)

// Helper macro for unused parameters if any, to avoid compiler warnings
#define UNUSED(x) (void)(x)

namespace netflow {

// --- Helper function to add TLV to PDU ---
// This simplifies PDU construction.
// The LldpTlvHeader itself handles the type/length packing.
static void add_tlv_to_pdu(std::vector<uint8_t>& pdu, uint8_t type, const std::vector<uint8_t>& value_data) {
    LldpTlvHeader tlv_header;
    tlv_header.setType(type);
    tlv_header.setLength(static_cast<uint16_t>(value_data.size()));

    uint16_t type_length_net = htons(tlv_header.type_length); // Convert to network byte order

    // Add TLV header
    const uint8_t* header_bytes = reinterpret_cast<const uint8_t*>(&type_length_net);
    pdu.insert(pdu.end(), header_bytes, header_bytes + sizeof(type_length_net));

    // Add TLV value
    pdu.insert(pdu.end(), value_data.begin(), value_data.end());
}

// --- LldpManager Implementation ---

LldpManager::LldpManager(Switch& owner_switch, InterfaceManager& if_mgr)
    : owner_switch_(owner_switch), interface_manager_(if_mgr) {
    // Initialization, if any, beyond member initialization
}

LldpManager::~LldpManager() {
    // Cleanup, if any
}

std::string LldpManager::get_system_name() const {
    // In a real system, this might come from ConfigManager or OS API
    return "NetFlowSwitch";
}

std::string LldpManager::get_system_description() const {
    // In a real system, this might come from ConfigManager or OS API
    return "NetFlow++ Switch Software";
}

std::vector<uint8_t> LldpManager::build_lldpdu(uint32_t port_id, const LldpPortConfig& config) {
    std::vector<uint8_t> pdu;

    // 1. Chassis ID TLV
    MacAddress chassis_mac = interface_manager_.get_port_mac(port_id); // Assuming base MAC or port MAC
    std::vector<uint8_t> chassis_id_value;
    chassis_id_value.push_back(CHASSIS_ID_SUBTYPE_MAC_ADDRESS);
    chassis_id_value.insert(chassis_id_value.end(), chassis_mac.octets.begin(), chassis_mac.octets.end());
    add_tlv_to_pdu(pdu, TLV_TYPE_CHASSIS_ID, chassis_id_value);

    // 2. Port ID TLV
    std::string port_name_str = interface_manager_.get_port_name(port_id);
    std::vector<uint8_t> port_id_value;
    port_id_value.push_back(PORT_ID_SUBTYPE_INTERFACE_NAME);
    port_id_value.insert(port_id_value.end(), port_name_str.begin(), port_name_str.end());
    add_tlv_to_pdu(pdu, TLV_TYPE_PORT_ID, port_id_value);

    // 3. TTL TLV
    uint16_t ttl_value_host = static_cast<uint16_t>(config.tx_interval_seconds * config.ttl_multiplier);
    uint16_t ttl_value_net = htons(ttl_value_host);
    std::vector<uint8_t> ttl_tlv_value;
    const uint8_t* ttl_bytes = reinterpret_cast<const uint8_t*>(&ttl_value_net);
    ttl_tlv_value.insert(ttl_tlv_value.end(), ttl_bytes, ttl_bytes + sizeof(ttl_value_net));
    add_tlv_to_pdu(pdu, TLV_TYPE_TTL, ttl_tlv_value);

    // 4. System Name TLV (Optional)
    std::string system_name_str = get_system_name();
    if (!system_name_str.empty()) {
        std::vector<uint8_t> system_name_value(system_name_str.begin(), system_name_str.end());
        add_tlv_to_pdu(pdu, TLV_TYPE_SYSTEM_NAME, system_name_value);
    }

    // 5. System Description TLV (Optional)
    std::string system_desc_str = get_system_description();
    if (!system_desc_str.empty()) {
        std::vector<uint8_t> system_desc_value(system_desc_str.begin(), system_desc_str.end());
        add_tlv_to_pdu(pdu, TLV_TYPE_SYSTEM_DESCRIPTION, system_desc_value);
    }

    // TODO: Could add Port Description TLV if interface_manager provides it.
    // std::string port_desc_str = interface_manager_.get_port_description(port_id);
    // if (!port_desc_str.empty()) {
    //    std::vector<uint8_t> port_desc_value(port_desc_str.begin(), port_desc_str.end());
    //    add_tlv_to_pdu(pdu, TLV_TYPE_PORT_DESCRIPTION, port_desc_value);
    // }


    // End of LLDPDU TLV
    add_tlv_to_pdu(pdu, TLV_TYPE_END_OF_LLDPDU, {});

    return pdu;
}

void LldpManager::parse_lldpdu(const uint8_t* data, size_t len, uint32_t ingress_port) {
    if (!data || len == 0) return;

    LldpNeighborInfo current_neighbor;
    current_neighbor.ingress_port = ingress_port;
    current_neighbor.last_updated = std::chrono::steady_clock::now();
    bool found_chassis_id = false;
    bool found_port_id = false;
    bool found_ttl = false;

    const uint8_t* ptr = data;
    size_t remaining_len = len;

    while (remaining_len >= sizeof(LldpTlvHeader)) {
        LldpTlvHeader tlv_header_net;
        std::copy(ptr, ptr + sizeof(LldpTlvHeader), reinterpret_cast<uint8_t*>(&tlv_header_net.type_length));

        LldpTlvHeader tlv_header; // For host byte order
        tlv_header.type_length = ntohs(tlv_header_net.type_length);

        uint8_t type = tlv_header.getType();
        uint16_t tlv_len_val = tlv_header.getLength();

        ptr += sizeof(LldpTlvHeader);
        remaining_len -= sizeof(LldpTlvHeader);

        if (tlv_len_val > remaining_len) {
            // Malformed TLV, length exceeds remaining PDU
            // std::cerr << "LLDP: Malformed TLV, length " << tlv_len_val << " exceeds remaining PDU " << remaining_len << std::endl;
            return;
        }

        if (type == TLV_TYPE_END_OF_LLDPDU) {
            break; // End of LLDPDU
        }

        const uint8_t* value_ptr = ptr;

        switch (type) {
            case TLV_TYPE_CHASSIS_ID:
                if (tlv_len_val >= 1) { // Subtype (1 byte) + ID
                    current_neighbor.chassis_id_subtype = *value_ptr;
                    current_neighbor.chassis_id_raw.assign(value_ptr + 1, value_ptr + tlv_len_val);
                    // current_neighbor.chassis_id_str = current_neighbor.getChassisIdString(); // Can be generated on demand
                    found_chassis_id = true;
                }
                break;
            case TLV_TYPE_PORT_ID:
                if (tlv_len_val >= 1) { // Subtype (1 byte) + ID
                    current_neighbor.port_id_subtype = *value_ptr;
                    current_neighbor.port_id_raw.assign(value_ptr + 1, value_ptr + tlv_len_val);
                    // current_neighbor.port_id_str = current_neighbor.getPortIdString(); // Can be generated on demand
                    found_port_id = true;
                }
                break;
            case TLV_TYPE_TTL:
                if (tlv_len_val == 2) {
                    uint16_t ttl_net;
                    std::copy(value_ptr, value_ptr + sizeof(uint16_t), reinterpret_cast<uint8_t*>(&ttl_net));
                    current_neighbor.ttl = ntohs(ttl_net);
                    found_ttl = true;
                }
                break;
            case TLV_TYPE_SYSTEM_NAME:
                current_neighbor.system_name.assign(reinterpret_cast<const char*>(value_ptr), tlv_len_val);
                break;
            case TLV_TYPE_SYSTEM_DESCRIPTION:
                current_neighbor.system_description.assign(reinterpret_cast<const char*>(value_ptr), tlv_len_val);
                break;
            case TLV_TYPE_PORT_DESCRIPTION:
                current_neighbor.port_description.assign(reinterpret_cast<const char*>(value_ptr), tlv_len_val);
                break;
            // Other TLVs (Management Address, etc.) can be added here
            default:
                // Unknown or unhandled TLV, skip
                break;
        }
        ptr += tlv_len_val;
        remaining_len -= tlv_len_val;
    }

    if (found_chassis_id && found_port_id && found_ttl) {
        std::lock_guard<std::mutex> lock(lldp_mutex_);
        auto& port_neighbors = neighbors_by_port_[ingress_port];

        if (current_neighbor.ttl == 0) { // Neighbor signaling shutdown or aged out
            port_neighbors.erase(std::remove_if(port_neighbors.begin(), port_neighbors.end(),
                [&](const LldpNeighborInfo& n) {
                    return n.chassis_id_raw == current_neighbor.chassis_id_raw &&
                           n.port_id_raw == current_neighbor.port_id_raw;
                }), port_neighbors.end());
            // std::cout << "LLDP: Removed neighbor due to TTL 0 on port " << ingress_port << std::endl;
            return;
        }

        auto it = std::find_if(port_neighbors.begin(), port_neighbors.end(),
            [&](const LldpNeighborInfo& n) {
                return n.chassis_id_raw == current_neighbor.chassis_id_raw &&
                       n.port_id_raw == current_neighbor.port_id_raw;
            });

        if (it != port_neighbors.end()) {
            // Update existing neighbor
            it->ttl = current_neighbor.ttl;
            it->system_name = current_neighbor.system_name;
            it->system_description = current_neighbor.system_description;
            it->port_description = current_neighbor.port_description;
            // Update other fields as necessary, e.g. management address
            it->last_updated = current_neighbor.last_updated;
            // std::cout << "LLDP: Updated neighbor on port " << ingress_port << std::endl;
        } else {
            // Add new neighbor
            // Generate string representations here or on demand when get_neighbors is called.
            // For now, they are generated by the getChassisIdString/getPortIdString methods in lldp_defs.hpp.
            port_neighbors.push_back(current_neighbor);
            // std::cout << "LLDP: New neighbor discovered on port " << ingress_port << std::endl;
        }
    } else {
        // std::cerr << "LLDP: Received PDU missing mandatory TLVs on port " << ingress_port << std::endl;
    }
}


void LldpManager::process_lldp_frame(const Packet& packet, uint32_t ingress_port) {
    LldpPortConfig port_config;
    {
        std::lock_guard<std::mutex> lock(lldp_mutex_);
        auto it = port_configs_.find(ingress_port);
        if (it == port_configs_.end() || !it->second.enabled) {
            return; // LLDP not enabled on this port
        }
        port_config = it->second; // Copy config
    }

    // Assuming packet.get_payload() returns a pointer to the start of the Ethernet payload (LLDPDU)
    // and packet.get_payload_length() returns its length.
    // This part is highly dependent on the Packet class structure.
    // For this example, let's assume Packet provides direct access to the LLDPDU part.
    // If the packet contains the Ethernet header, we'd need to skip it.
    // LLDP_ETHERTYPE (0x88CC) should have already been checked by the caller to identify this as an LLDP frame.

    // const uint8_t* lldpdu_data = packet.data() + ETH_HEADER_LEN; // Example if Packet::data() is start of frame
    // size_t lldpdu_len = packet.size() - ETH_HEADER_LEN;

    // Simpler assumption: packet.get_payload_data() gives start of LLDPDU
    // This requires the Packet object to have parsed up to the Ethernet payload.
    const uint8_t* lldpdu_data = packet.get_payload_data();
    size_t lldpdu_len = packet.get_payload_length();

    if (!lldpdu_data || lldpdu_len == 0) {
        // std::cerr << "LLDP: No payload data in packet on port " << ingress_port << std::endl;
        return;
    }

    parse_lldpdu(lldpdu_data, lldpdu_len, ingress_port);
}

void LldpManager::send_lldp_frame(uint32_t port_id) {
    LldpPortConfig config;
    {
        std::lock_guard<std::mutex> lock(lldp_mutex_);
        auto it = port_configs_.find(port_id);
        if (it == port_configs_.end() || !it->second.enabled) {
            // std::cerr << "LLDP: Sending frame on disabled/unconfigured port " << port_id << std::endl;
            return;
        }
        if (!interface_manager_.is_port_up(port_id)) {
            // std::cerr << "LLDP: Port " << port_id << " is down, not sending LLDP frame." << std::endl;
            return;
        }
        config = it->second; // Copy config
    }

    std::vector<uint8_t> pdu = build_lldpdu(port_id, config);

    if (pdu.empty()) {
        // std::cerr << "LLDP: Failed to build PDU for port " << port_id << std::endl;
        return;
    }

    // Actual sending mechanism:
    // This assumes InterfaceManager has a method to send a raw frame.
    // The source MAC should be the MAC of the egress port.
    MacAddress src_mac = interface_manager_.get_port_mac(port_id);

    // The send_frame function in InterfaceManager would encapsulate this PDU
    // into an Ethernet frame with dst_mac=LLDP_MULTICAST_MAC, src_mac, ethertype=LLDP_ETHERTYPE.
    // interface_manager_.send_frame(port_id, LLDP_MULTICAST_MAC, src_mac, LLDP_ETHERTYPE, pdu.data(), pdu.size());
    // Instead, call Switch's method to send the control plane frame
    auto src_mac_opt = interface_manager_.get_interface_mac(port_id);
    if (src_mac_opt) {
        owner_switch_.send_control_plane_frame(port_id, LLDP_MULTICAST_MAC, src_mac_opt.value(), LLDP_ETHERTYPE, pdu);
        // std::cout << "LLDP: Frame queued for sending via Switch on port " << port_id << " (Size: " << pdu.size() << " bytes)" << std::endl;
    } else {
        // std::cerr << "LLDP: Failed to get source MAC for port " << port_id << ", cannot send frame." << std::endl;
    }
}

void LldpManager::configure_port(uint32_t port_id, bool enabled, uint32_t tx_interval, uint32_t ttl_multiplier) {
    std::lock_guard<std::mutex> lock(lldp_mutex_);
    LldpPortConfig& config = port_configs_[port_id]; // Get or create
    config.enabled = enabled;
    config.tx_interval_seconds = tx_interval;
    config.ttl_multiplier = ttl_multiplier;
    if (enabled) {
        // Start sending quickly, then fall into regular interval.
        config.next_tx_time = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    }
    // std::cout << "LLDP: Port " << port_id << " configured. Enabled: " << enabled << std::endl;
}

LldpPortConfig LldpManager::get_port_config(uint32_t port_id) const {
    std::lock_guard<std::mutex> lock(lldp_mutex_);
    auto it = port_configs_.find(port_id);
    if (it != port_configs_.end()) {
        return it->second;
    }
    return LldpPortConfig{}; // Return default if not found
}

void LldpManager::expire_neighbors() {
    std::lock_guard<std::mutex> lock(lldp_mutex_);
    auto now = std::chrono::steady_clock::now();

    for (auto& pair : neighbors_by_port_) {
        auto& neighbors_vec = pair.second;
        neighbors_vec.erase(
            std::remove_if(neighbors_vec.begin(), neighbors_vec.end(),
                [&](const LldpNeighborInfo& neighbor) {
                    return now > (neighbor.last_updated + std::chrono::seconds(neighbor.ttl));
                }),
            neighbors_vec.end());
    }
}

void LldpManager::handle_timer_tick() {
    expire_neighbors(); // First, remove any aged-out neighbors

    std::vector<uint32_t> ports_to_send;
    {
        std::lock_guard<std::mutex> lock(lldp_mutex_);
        auto now = std::chrono::steady_clock::now();
        for (auto& pair : port_configs_) {
            uint32_t port_id = pair.first;
            LldpPortConfig& config = pair.second;

            if (config.enabled && now >= config.next_tx_time) {
                if (interface_manager_.is_port_up(port_id)) { // Check if port is administratively/operationally up
                    ports_to_send.push_back(port_id);
                    config.next_tx_time = now + std::chrono::seconds(config.tx_interval_seconds);
                } else {
                     // If port is down, reschedule for a short period to re-check,
                     // rather than skipping until next full interval.
                    config.next_tx_time = now + std::chrono::seconds(5); // Check again in 5s
                }
            }
        }
    }

    // Send frames outside the critical section to minimize lock holding time
    for (uint32_t port_id : ports_to_send) {
        send_lldp_frame(port_id);
    }
}

std::vector<LldpNeighborInfo> LldpManager::get_neighbors(uint32_t port_id) const {
    std::lock_guard<std::mutex> lock(lldp_mutex_);
    auto it = neighbors_by_port_.find(port_id);
    if (it != neighbors_by_port_.end()) {
        return it->second; // Return a copy
    }
    return {}; // Empty vector if no neighbors or port not found
}

std::map<uint32_t, std::vector<LldpNeighborInfo>> LldpManager::get_all_neighbors() const {
    std::lock_guard<std::mutex> lock(lldp_mutex_);
    return neighbors_by_port_; // Return a copy
}

} // namespace netflow
