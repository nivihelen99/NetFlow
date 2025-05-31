#include "netflow++/lacp_manager.hpp"
#include "netflow++/packet.hpp"      // For Packet, EthernetHeader (if needed directly, though LACPDU is main focus)
#include "netflow++/buffer_pool.hpp" // For BufferPool (if generate_lacpdus is also moved here later)
#include "netflow++/logger.hpp"      // For SwitchLogger (if logging is added)
#include <iostream> // For temporary logging during development
#include <cstring>  // For memcpy
#include <algorithm> // For std::sort, std::remove, std::unique for LagConfig member_ports

// Assuming arpa/inet.h for htons/ntohs is included via packet.hpp or lacp_manager.hpp indirectly
// If not, it might be needed here or in lacp_manager.hpp for Lacpdu struct methods.

namespace netflow {

// Default constructor for Lacpdu (if not inline in header)
Lacpdu::Lacpdu() {
    std::memset(this, 0, sizeof(Lacpdu));
    subtype = LacpDefaults::LACP_SUBTYPE;
    version_number = LacpDefaults::LACP_VERSION;
    tlv_type_actor = 0x01; actor_info_length = 0x14; // 20 bytes
    tlv_type_partner = 0x02; partner_info_length = 0x14; // 20 bytes
    tlv_type_collector = 0x03; collector_info_length = 0x10; // 16 bytes
    tlv_type_terminator = 0x00; terminator_length = 0x00;
}

// get_actor_system_id for Lacpdu (if not inline)
uint64_t Lacpdu::get_actor_system_id() const {
    uint64_t mac_part = 0;
    for(int i=0; i<6; ++i) mac_part = (mac_part << 8) | actor_system_mac[i];
    // Priority is the high part of System ID
    return (static_cast<uint64_t>(ntohs(actor_system_priority)) << 48) | mac_part;
}

// set_actor_system_id for Lacpdu (if not inline)
void Lacpdu::set_actor_system_id(uint64_t system_id) {
    actor_system_priority = htons(static_cast<uint16_t>((system_id >> 48) & 0xFFFF));
    for(int i=0; i<6; ++i) actor_system_mac[5-i] = (system_id >> (i*8)) & 0xFF;
}


// Constructor for LacpPortInfo (if not inline)
LacpPortInfo::LacpPortInfo(uint32_t phys_id)
    : port_id_physical(phys_id),
      actor_system_id_val(0), actor_port_id_val(0), actor_key_val(0), actor_state_val(0),
      partner_system_id_val(0), partner_port_id_val(0), partner_key_val(0), partner_state_val(0),
      is_active_member_of_lag(false), current_aggregator_id(0),
      current_while_timer_ticks(0), short_timeout_timer_ticks(0), long_timeout_timer_ticks(0),
      mux_state(MuxMachineState::DETACHED),
      rx_state(RxMachineState::INITIALIZE),
      periodic_tx_state(PeriodicTxState::NO_PERIODIC),
      port_priority_val(128) // Default LACP port priority
{
    // Default actor state: Aggregation=1, Defaulted=1. Others depend on config/runtime.
    actor_state_val = LacpStateFlag::AGGREGATION | LacpStateFlag::DEFAULTED;
    // Default partner state: Defaulted=1, Expired=1 (as we haven't heard from them)
    partner_state_val = LacpStateFlag::DEFAULTED | LacpStateFlag::EXPIRED;
}

void LacpPortInfo::set_actor_state_flag(LacpStateFlag flag, bool set) {
    if (set) actor_state_val |= static_cast<uint8_t>(flag);
    else actor_state_val &= ~static_cast<uint8_t>(flag);
}

bool LacpPortInfo::get_actor_state_flag(LacpStateFlag flag) const {
    return (actor_state_val & static_cast<uint8_t>(flag)) != 0;
}


// --- LacpManager Constructor Definition ---
LacpManager::LacpManager(uint64_t switch_base_mac, uint16_t system_priority)
    : switch_mac_address_(switch_base_mac),
      lacp_system_priority_(system_priority) {
    // Combine priority and MAC to form the Actor System ID
    // LACP System ID = 16-bit System Priority + 48-bit MAC Address
    actor_system_id_ = (static_cast<uint64_t>(lacp_system_priority_) << 48) |
                       (switch_mac_address_ & 0x0000FFFFFFFFFFFFULL);
    // std::cout << "LacpManager initialized. Actor System ID: " << std::hex << actor_system_id_ << std::dec << std::endl;
}

// Other LacpManager method definitions will go here...
// For example: create_lag, add_port_to_lag, process_lacpdu, generate_lacpdus, etc.
// These were already present in the header in a simplified form or defined in a previous .cpp file.
// For this subtask, only the constructor is strictly required to be defined here.
// The select_egress_port, process_lacpdu were defined inline in the header.
// generate_lacpdus, run_lacp_timers_and_statemachines etc. are still missing declarations in the header.
// We should ensure those definitions are also present if this file is being created fresh.
// For now, focusing on the constructor as per the subtask step.

void LacpManager::set_logger(SwitchLogger* logger) {
    logger_ = logger;
}

bool LacpManager::create_lag(LagConfig& config) {
    if (config.lag_id == 0) {
        if (logger_) logger_->warning("LACP", "Attempt to create LAG with ID 0 failed.");
        return false;
    }
    if (lags_.count(config.lag_id)) {
        if (logger_) logger_->error("LACP", "LAG ID " + std::to_string(config.lag_id) + " already exists.");
        return false;
    }

    for (uint32_t port_id : config.member_ports) {
        if (port_to_lag_map_.count(port_id)) {
            if (logger_) logger_->error("LACP", "Port " + std::to_string(port_id) + " is already part of LAG " + std::to_string(port_to_lag_map_[port_id]));
            return false;
        }
    }

    lags_[config.lag_id] = config;
    std::sort(lags_[config.lag_id].member_ports.begin(), lags_[config.lag_id].member_ports.end());
    lags_[config.lag_id].member_ports.erase(
        std::unique(lags_[config.lag_id].member_ports.begin(), lags_[config.lag_id].member_ports.end()),
        lags_[config.lag_id].member_ports.end()
    );

    for (uint32_t port_id : lags_[config.lag_id].member_ports) {
        port_to_lag_map_[port_id] = config.lag_id;
        // Also initialize LACP port info for this port
        initialize_lacp_port_info(port_id, lags_[config.lag_id]);
    }
    if (logger_) logger_->info("LACP", "LAG " + std::to_string(config.lag_id) + " created.");
    return true;
}

bool LacpManager::add_port_to_lag(uint32_t lag_id, uint32_t port_id) {
    auto lag_it = lags_.find(lag_id);
    if (lag_it == lags_.end()) {
        if (logger_) logger_->error("LACP", "LAG " + std::to_string(lag_id) + " does not exist, cannot add port " + std::to_string(port_id));
        return false;
    }

    auto port_map_it = port_to_lag_map_.find(port_id);
    if (port_map_it != port_to_lag_map_.end()) {
        if (port_map_it->second == lag_id) {
            if (logger_) logger_->debug("LACP", "Port " + std::to_string(port_id) + " already in LAG " + std::to_string(lag_id));
            return true; // Port already in this LAG
        } else {
            if (logger_) logger_->error("LACP", "Port " + std::to_string(port_id) + " is already part of a different LAG (" + std::to_string(port_map_it->second) + ").");
            return false; // Port already in a different LAG
        }
    }

    lag_it->second.member_ports.push_back(port_id);
    std::sort(lag_it->second.member_ports.begin(), lag_it->second.member_ports.end());
    lag_it->second.member_ports.erase(
        std::unique(lag_it->second.member_ports.begin(), lag_it->second.member_ports.end()),
        lag_it->second.member_ports.end()
    );
    port_to_lag_map_[port_id] = lag_id;
    initialize_lacp_port_info(port_id, lag_it->second);
    if (logger_) logger_->info("LACP", "Port " + std::to_string(port_id) + " added to LAG " + std::to_string(lag_id));
    return true;
}

bool LacpManager::remove_port_from_lag(uint32_t lag_id, uint32_t port_id) {
    auto lag_it = lags_.find(lag_id);
    if (lag_it == lags_.end()) {
        if (logger_) logger_->warning("LACP", "LAG " + std::to_string(lag_id) + " not found for port " + std::to_string(port_id) + " removal.");
        return false;
    }

    auto port_map_it = port_to_lag_map_.find(port_id);
    if (port_map_it == port_to_lag_map_.end() || port_map_it->second != lag_id) {
        if (logger_) logger_->warning("LACP", "Port " + std::to_string(port_id) + " is not part of LAG " + std::to_string(lag_id));
        return false;
    }

    auto& members = lag_it->second.member_ports;
    members.erase(std::remove(members.begin(), members.end(), port_id), members.end());
    port_to_lag_map_.erase(port_id);
    port_lacp_info_.erase(port_id); // Remove LACP specific info for the port

    if (logger_) logger_->info("LACP", "Port " + std::to_string(port_id) + " removed from LAG " + std::to_string(lag_id));
    if (members.empty()) {
        if (logger_) logger_->warning("LACP", "LAG " + std::to_string(lag_id) + " has no more members.");
    }
    return true;
}

void LacpManager::delete_lag(uint32_t lag_id) {
    auto lag_it = lags_.find(lag_id);
    if (lag_it != lags_.end()) {
        for (uint32_t port_id : lag_it->second.member_ports) {
            port_to_lag_map_.erase(port_id);
            port_lacp_info_.erase(port_id);
        }
        lags_.erase(lag_id);
        if (logger_) logger_->info("LACP", "LAG " + std::to_string(lag_id) + " deleted.");
    } else {
        if (logger_) logger_->warning("LACP", "Attempt to delete non-existent LAG ID " + std::to_string(lag_id));
    }
}

uint32_t LacpManager::select_egress_port(uint32_t lag_id, const Packet& pkt) const {
    auto it = lags_.find(lag_id);
    if (it == lags_.end() || it->second.member_ports.empty()) {
        if (logger_) logger_->error("LACP", "Invalid LAG ID " + std::to_string(lag_id) + " or no member ports for selection.");
        return 0;
    }

    const LagConfig& lag_config = it->second;

    // Use the dynamically updated active_distributing_members list
    const std::vector<uint32_t>& members_to_use = lag_config.active_distributing_members;

    if (members_to_use.empty()) {
        if (logger_) logger_->warning("LACP", "LAG " + std::to_string(lag_id) + ": No active distributing members available for port selection. No port selected.");
        return 0; // No port can be selected
    }

    uint32_t hash_value = 0;
    // Retrieve headers - these calls also set l2_header_size_ and current_offset_ in pkt
    const EthernetHeader* eth_hdr = pkt.ethernet(); // Needed for L2 hashes, and to ensure l2_header_size is set
    const IPv4Header* ip4_hdr = pkt.ipv4(); // Sets current_offset to start of L4 if IPv4
    const IPv6Header* ip6_hdr = ip4_hdr ? nullptr : pkt.ipv6(); // Try IPv6 only if not IPv4
    const TcpHeader* tcp_hdr = nullptr;
    const UdpHeader* udp_hdr = nullptr;
    uint8_t l3_protocol = 0;

    if (ip4_hdr) {
        l3_protocol = ip4_hdr->protocol;
        // current_offset in pkt is now at L4 (after ipv4() call)
        if (l3_protocol == 6) tcp_hdr = pkt.tcp(); // pkt.tcp() will use current_offset
        else if (l3_protocol == 17) udp_hdr = pkt.udp(); // pkt.udp() will use current_offset
    } else if (ip6_hdr) {
        l3_protocol = ip6_hdr->next_header;
        // current_offset in pkt is now at L4 (after ipv6() call)
        if (l3_protocol == 6) tcp_hdr = pkt.tcp();
        else if (l3_protocol == 17) udp_hdr = pkt.udp();
    }


    // XOR sum hashing helper
    auto xor_bytes = [](const uint8_t* data, size_t len, uint32_t current_hash) -> uint32_t {
        for (size_t i = 0; i < len; ++i) {
            current_hash ^= data[i];
        }
        return current_hash;
    };
    auto xor_u16 = [](uint16_t val, uint32_t current_hash) -> uint32_t {
        current_hash ^= (val & 0xFF);
        current_hash ^= ((val >> 8) & 0xFF);
        return current_hash;
    };
    auto xor_u32 = [](uint32_t val, uint32_t current_hash) -> uint32_t {
        current_hash ^= (val & 0xFF);
        current_hash ^= ((val >> 8) & 0xFF);
        current_hash ^= ((val >> 16) & 0xFF);
        current_hash ^= ((val >> 24) & 0xFF);
        return current_hash;
    };


    switch (lag_config.hash_mode) {
        case LacpHashMode::SRC_MAC:
            if (eth_hdr && pkt.src_mac().has_value()) {
                hash_value = xor_bytes(pkt.src_mac().value().bytes, 6, hash_value);
            }
            break;
        case LacpHashMode::DST_MAC:
            if (eth_hdr && pkt.dst_mac().has_value()) {
                hash_value = xor_bytes(pkt.dst_mac().value().bytes, 6, hash_value);
            }
            break;
        case LacpHashMode::SRC_DST_MAC:
            if (eth_hdr) {
                if (pkt.src_mac().has_value()) hash_value = xor_bytes(pkt.src_mac().value().bytes, 6, hash_value);
                if (pkt.dst_mac().has_value()) hash_value = xor_bytes(pkt.dst_mac().value().bytes, 6, hash_value);
            }
            break;
        case LacpHashMode::SRC_IP:
            if (ip4_hdr) hash_value = xor_u32(ntohl(ip4_hdr->src_ip), hash_value);
            else if (ip6_hdr) { // XOR fold IPv6 address
                 for(int i=0; i<4; ++i) hash_value = xor_u32(ntohl(reinterpret_cast<const uint32_t*>(ip6_hdr->src_ip)[i]), hash_value);
            }
            break;
        case LacpHashMode::DST_IP:
            if (ip4_hdr) hash_value = xor_u32(ntohl(ip4_hdr->dst_ip), hash_value);
            else if (ip6_hdr) {
                 for(int i=0; i<4; ++i) hash_value = xor_u32(ntohl(reinterpret_cast<const uint32_t*>(ip6_hdr->dst_ip)[i]), hash_value);
            }
            break;
        case LacpHashMode::SRC_DST_IP:
            if (ip4_hdr) {
                hash_value = xor_u32(ntohl(ip4_hdr->src_ip), hash_value);
                hash_value = xor_u32(ntohl(ip4_hdr->dst_ip), hash_value);
            } else if (ip6_hdr) {
                for(int i=0; i<4; ++i) hash_value = xor_u32(ntohl(reinterpret_cast<const uint32_t*>(ip6_hdr->src_ip)[i]), hash_value);
                for(int i=0; i<4; ++i) hash_value = xor_u32(ntohl(reinterpret_cast<const uint32_t*>(ip6_hdr->dst_ip)[i]), hash_value);
            }
            break;
        case LacpHashMode::SRC_PORT:
            if (tcp_hdr) hash_value = xor_u16(ntohs(tcp_hdr->src_port), hash_value);
            else if (udp_hdr) hash_value = xor_u16(ntohs(udp_hdr->src_port), hash_value);
            break;
        case LacpHashMode::DST_PORT:
            if (tcp_hdr) hash_value = xor_u16(ntohs(tcp_hdr->dst_port), hash_value);
            else if (udp_hdr) hash_value = xor_u16(ntohs(udp_hdr->dst_port), hash_value);
            break;
        case LacpHashMode::SRC_DST_PORT:
            if (tcp_hdr) {
                hash_value = xor_u16(ntohs(tcp_hdr->src_port), hash_value);
                hash_value = xor_u16(ntohs(tcp_hdr->dst_port), hash_value);
            } else if (udp_hdr) {
                hash_value = xor_u16(ntohs(udp_hdr->src_port), hash_value);
                hash_value = xor_u16(ntohs(udp_hdr->dst_port), hash_value);
            }
            break;
        case LacpHashMode::SRC_DST_IP_L4_PORT: // 5-tuple
            if (ip4_hdr) {
                hash_value = xor_u32(ntohl(ip4_hdr->src_ip), hash_value);
                hash_value = xor_u32(ntohl(ip4_hdr->dst_ip), hash_value);
                hash_value ^= ip4_hdr->protocol;
            } else if (ip6_hdr) {
                for(int i=0; i<4; ++i) hash_value = xor_u32(ntohl(reinterpret_cast<const uint32_t*>(ip6_hdr->src_ip)[i]), hash_value);
                for(int i=0; i<4; ++i) hash_value = xor_u32(ntohl(reinterpret_cast<const uint32_t*>(ip6_hdr->dst_ip)[i]), hash_value);
                hash_value ^= ip6_hdr->next_header;
            }
            if (tcp_hdr) {
                hash_value = xor_u16(ntohs(tcp_hdr->src_port), hash_value);
                hash_value = xor_u16(ntohs(tcp_hdr->dst_port), hash_value);
            } else if (udp_hdr) {
                hash_value = xor_u16(ntohs(udp_hdr->src_port), hash_value);
                hash_value = xor_u16(ntohs(udp_hdr->dst_port), hash_value);
            }
            break;
        default: // Fallback to L2 SRC_DST_MAC if unknown mode or packet doesn't match
            if (logger_) logger_->debug("LACP", "LAG " + std::to_string(lag_id) + ": Unknown or inapplicable hash mode "
                                             + std::to_string(static_cast<int>(lag_config.hash_mode)) + ". Falling back to L2 hash.");
            if (eth_hdr) {
                 if (pkt.src_mac().has_value()) hash_value = xor_bytes(pkt.src_mac().value().bytes, 6, hash_value);
                 if (pkt.dst_mac().has_value()) hash_value = xor_bytes(pkt.dst_mac().value().bytes, 6, hash_value);
            }
            break;
    }

    // If after all hashing attempts hash_value is still 0 (e.g. non-IP/TCP/UDP packet for L3/L4 hash modes)
    // use a very basic hash from packet pointer or length to ensure some distribution.
    // Or, more simply, if eth_hdr is present, use its address components if hash_value is 0.
    if (hash_value == 0 && eth_hdr) {
        if (pkt.src_mac().has_value()) { // Default if specific fields were missing
            for(int i=0; i<6; ++i) hash_value += pkt.src_mac().value().bytes[i]; // Simple sum as last resort
        }
    }


    uint32_t selected_index = hash_value % members_to_use.size();
    uint32_t selected_port_id = members_to_use[selected_index];

    if (logger_) {
        logger_->info("LACP", "LAG " + std::to_string(lag_id) +
                              ": HashMode=" + std::to_string(static_cast<int>(lag_config.hash_mode)) +
                              ", HashValue=" + std::to_string(hash_value) +
                              ", ActiveMembers=" + std::to_string(members_to_use.size()) +
                              ", SelectedIndex=" + std::to_string(selected_index) +
                              ", SelectedPort=" + std::to_string(selected_port_id));
    }

    return selected_port_id;
}

void LacpManager::process_lacpdu(const Packet& lacpdu_packet, uint32_t ingress_port_id) {
    if (logger_) {
        logger_->debug("LACP", "Received LACPDU on port " + std::to_string(ingress_port_id) +
                              ". Size: " + std::to_string(lacpdu_packet.get_buffer()->get_data_length()));
    }

    PacketBuffer* raw_buffer = lacpdu_packet.get_buffer();
    if (!raw_buffer) {
        if (logger_) logger_->error("LACP", "Received LACPDU on port " + std::to_string(ingress_port_id) + " has null buffer.");
        return;
    }

    // Determine L2 header size (Ethernet + optional VLAN)
    // The Packet class's ethernet() method updates l2_header_size_ internally.
    // We don't need the EthernetHeader pointer itself here, but calling ethernet() ensures
    // l2_header_size_ is calculated correctly.
    lacpdu_packet.ethernet(); // This will set the internal l2_header_size_ in the packet object.
                              // However, the packet object is const here. We need a way to get this.
                              // For now, assume fixed EthernetHeader::SIZE.
                              // A better solution would be for Packet to expose its calculated l2_header_size_
                              // or for this function to parse it.
    // TODO: Robustly determine L2 header size, considering VLAN tags.
    // For this iteration, assuming no VLAN tags or they are already stripped.
    size_t l2_header_offset = EthernetHeader::SIZE;
    if (lacpdu_packet.has_vlan()){ // Check if packet has vlan
        l2_header_offset += VlanHeader::SIZE;
    }


    if (raw_buffer->get_data_length() < l2_header_offset + LACPDU_MIN_SIZE) {
        if (logger_) logger_->warning("LACP", "Port " + std::to_string(ingress_port_id) + ": LACPDU too short. Length: " +
                                               std::to_string(raw_buffer->get_data_length()));
        return;
    }

    const unsigned char* eth_payload_ptr = static_cast<const unsigned char*>(raw_buffer->get_data_start_ptr()) + l2_header_offset;
    const Lacpdu* pdu = reinterpret_cast<const Lacpdu*>(eth_payload_ptr);

    // Validate LACPDU
    if (pdu->subtype != LacpDefaults::LACP_SUBTYPE) {
        if (logger_) logger_->warning("LACP", "Port " + std::to_string(ingress_port_id) + ": Invalid LACPDU subtype: " + std::to_string(pdu->subtype));
        return;
    }
    if (pdu->version_number != LacpDefaults::LACP_VERSION) {
        if (logger_) logger_->warning("LACP", "Port " + std::to_string(ingress_port_id) + ": Invalid LACPDU version: " + std::to_string(pdu->version_number));
        return;
    }

    // Update Port Information
    auto port_info_it = port_lacp_info_.find(ingress_port_id);
    if (port_info_it == port_lacp_info_.end()) {
        if (logger_) logger_->error("LACP", "Port " + std::to_string(ingress_port_id) + ": No LACP info found for port receiving LACPDU.");
        return;
    }
    LacpPortInfo& port_info = port_info_it->second;

    // The PDU's Actor info is our Partner's info
    port_info.partner_system_id_val = pdu->get_actor_system_id();
    port_info.partner_key_val = ntohs(pdu->actor_key);
    // Combine priority and port number into partner_port_id_val (uint32_t)
    // High 16 bits for priority, low 16 bits for port number
    port_info.partner_port_id_val = (static_cast<uint32_t>(ntohs(pdu->actor_port_priority)) << 16) | ntohs(pdu->actor_port_number);
    port_info.partner_state_val = pdu->actor_state;

    if (logger_) {
        logger_->debug("LACP", "Port " + std::to_string(ingress_port_id) +
                               ": Updated partner info: SysID=0x" +
                               std::to_string(port_info.partner_system_id_val) + // Potentially needs hex formatting
                               ", Key=" + std::to_string(port_info.partner_key_val) +
                               ", PortID=" + std::to_string(ntohs(pdu->actor_port_number)) + // Log port number directly
                               ", State=0x" + std::to_string(port_info.partner_state_val)); // Potentially needs hex
    }

    // Compare PDU's Partner info (what they think about us) with our Actor info
    // actor_system_id_ is uint64_t (Prio_16bit | MAC_48bit)
    uint16_t pdu_partner_sys_prio = ntohs(pdu->partner_system_priority);
    uint64_t pdu_partner_mac = 0;
    for(int i=0; i<6; ++i) pdu_partner_mac = (pdu_partner_mac << 8) | pdu->partner_system_mac[i];
    uint64_t pdu_partner_system_id = (static_cast<uint64_t>(pdu_partner_sys_prio) << 48) | pdu_partner_mac;

    if (pdu_partner_system_id != 0 && pdu_partner_system_id != actor_system_id_) {
        if (logger_) logger_->warning("LACP", "Port " + std::to_string(ingress_port_id) +
                                               ": Partner's view of my System ID mismatch. Theirs: 0x" +
                                               std::to_string(pdu_partner_system_id) + // Hex format
                                               ", Mine: 0x" + std::to_string(actor_system_id_)); // Hex format
    }
    if (ntohs(pdu->partner_key) != 0 && ntohs(pdu->partner_key) != port_info.actor_key_val) {
         if (logger_) logger_->warning("LACP", "Port " + std::to_string(ingress_port_id) +
                                               ": Partner's view of my Key mismatch. Theirs: " +
                                               std::to_string(ntohs(pdu->partner_key)) +
                                               ", Mine: " + std::to_string(port_info.actor_key_val));
    }
    // Compare port number and priority separately
    uint16_t pdu_partner_port_num = ntohs(pdu->partner_port_number);
    uint16_t pdu_partner_port_prio = ntohs(pdu->partner_port_priority);
    // Our port ID is simply ingress_port_id, priority is port_info.port_priority_val
    if (pdu_partner_port_num != 0 && pdu_partner_port_num != static_cast<uint16_t>(ingress_port_id)) {
         if (logger_) logger_->warning("LACP", "Port " + std::to_string(ingress_port_id) +
                                               ": Partner's view of my Port Number mismatch. Theirs: " +
                                               std::to_string(pdu_partner_port_num) +
                                               ", Mine: " + std::to_string(ingress_port_id));
    }
    if (pdu_partner_port_prio != 0 && pdu_partner_port_prio != port_info.port_priority_val) {
        if (logger_) logger_->warning("LACP", "Port " + std::to_string(ingress_port_id) +
                                               ": Partner's view of my Port Priority mismatch. Theirs: " +
                                               std::to_string(pdu_partner_port_prio) +
                                               ", Mine: " + std::to_string(port_info.port_priority_val));
    }
    if (pdu->partner_state != 0 && pdu->partner_state != port_info.actor_state_val) {
        // Note: Partner might not have all state flags set if it just came up or if LACP negotiation is ongoing
        // This might be noisy. Could be a debug level log.
        if (logger_) logger_->debug("LACP", "Port " + std::to_string(ingress_port_id) +
                                               ": Partner's view of my State mismatch. Theirs: 0x" +
                                               std::to_string(pdu->partner_state) + // Hex format
                                               ", Mine: 0x" + std::to_string(port_info.actor_state_val)); // Hex format
    }

    // Trigger Rx State Machine
    run_lacp_rx_machine(ingress_port_id);
}

// Placeholder definitions for other methods.
// These would need their full logic from the previous LACP subtask AND declarations in the header.

std::vector<Packet> LacpManager::generate_lacpdus(BufferPool& buffer_pool) {
    if (logger_) logger_->debug("LACP", "generate_lacpdus called");
    std::vector<Packet> lacpdus_to_send;

    for (auto& port_info_pair : port_lacp_info_) {
        uint32_t port_id = port_info_pair.first;
        LacpPortInfo& port_info = port_info_pair.second;

        if (port_info.periodic_tx_state == LacpPortInfo::PeriodicTxState::PERIODIC_TX) {
            if (logger_) logger_->debug("LACP", "Port " + std::to_string(port_id) + " requires LACPDU transmission.");

            // Allocate buffer: Ethernet Header + LACPDU payload
            // LACPDU_MIN_SIZE is a reasonable approximation, though actual size could be larger
            // if all reserved fields were used. The struct size is fixed though.
            size_t buffer_size = EthernetHeader::SIZE + sizeof(Lacpdu);
            PacketBuffer* pb = buffer_pool.allocate_buffer(buffer_size);
            if (!pb) {
                if (logger_) logger_->error("LACP", "Failed to allocate buffer for LACPDU for port " + std::to_string(port_id));
                continue; // Skip this PDU if no buffer
            }
            pb->set_data_len(buffer_size); // Set the actual used length

            // Construct Ethernet Header
            EthernetHeader* eth_hdr = reinterpret_cast<EthernetHeader*>(pb->get_data_start_ptr());
            // Destination MAC
            uint64_t dest_mac_val = LacpDefaults::LACP_MULTICAST_MAC;
            for (int i = 5; i >= 0; --i) {
                eth_hdr->dst_mac.bytes[i] = (dest_mac_val >> ( (5-i) * 8) ) & 0xFF;
            }
            // Source MAC: Use switch base MAC for now. A more specific port MAC might be needed.
            // This assumes switch_mac_address_ is the base MAC for the system.
            // If each port has a unique MAC, it should be retrieved from an InterfaceManager or similar.
            uint64_t src_mac_val = switch_mac_address_; // Member of LacpManager
            for (int i = 5; i >= 0; --i) {
                eth_hdr->src_mac.bytes[i] = (src_mac_val >> ( (5-i) * 8) ) & 0xFF;
            }
            eth_hdr->ethertype = htons(LacpDefaults::LACP_ETHERTYPE);

            // Construct LACPDU payload
            Lacpdu* lacpdu_payload = reinterpret_cast<Lacpdu*>(pb->get_data_start_ptr() + EthernetHeader::SIZE);

            // Initialize with defaults (subtype, version, TLV types/lengths, terminator)
            new (lacpdu_payload) Lacpdu(); // Placement new to call constructor

            // Actor Information
            lacpdu_payload->set_actor_system_id(actor_system_id_); // Uses manager's system ID

            // Actor Key: from LagConfig or LacpPortInfo
            // Assuming actor_key_val in LacpPortInfo is authoritative if set, else from LagConfig's admin key
            auto lag_id_opt = get_lag_for_port(port_id);
            if (lag_id_opt) {
                auto lag_cfg_opt = get_lag_config(lag_id_opt.value());
                if (lag_cfg_opt) {
                    // Use port_info.actor_key_val if it's specifically set (e.g. by selection logic),
                    // otherwise, default to the LAG's configured admin key.
                    // For now, let's assume actor_key_val in port_info is the operational key.
                    lacpdu_payload->actor_key = htons(port_info.actor_key_val);
                     if (port_info.actor_key_val == 0 && lag_cfg_opt->actor_admin_key != 0) {
                        // If port_info.actor_key_val is not yet operationally set,
                        // and there is an admin key, perhaps use admin key?
                        // LACP standard: admin key is used if operational key is not yet derived.
                        // For simplicity, let's assume port_info.actor_key_val is updated by selection logic.
                        // If it's 0, it might mean it's not part of an aggregate yet.
                        // Using the value directly from port_info.actor_key_val.
                    }
                }
            }
            if (lacpdu_payload->actor_key == 0 && lag_id_opt) { // Fallback if not set via port_info
                 auto lag_cfg_opt = get_lag_config(lag_id_opt.value());
                 if (lag_cfg_opt) lacpdu_payload->actor_key = htons(lag_cfg_opt->actor_admin_key);
            }


            lacpdu_payload->actor_port_priority = htons(port_info.port_priority_val); // From LacpPortInfo
            lacpdu_payload->actor_port_number = htons(static_cast<uint16_t>(port_id)); // Use physical port_id as LACP port number
            lacpdu_payload->actor_state = port_info.actor_state_val;

            // Partner Information (if known)
            if (port_info.partner_system_id_val != 0) { // Check if partner info is populated
                // Convert partner_system_id_val (uint64_t) to priority and MAC for LACPDU
                uint16_t partner_sys_prio = static_cast<uint16_t>((port_info.partner_system_id_val >> 48) & 0xFFFF);
                lacpdu_payload->partner_system_priority = htons(partner_sys_prio);
                for (int i = 0; i < 6; ++i) {
                    lacpdu_payload->partner_system_mac[5 - i] = (port_info.partner_system_id_val >> (i * 8)) & 0xFF;
                }
                lacpdu_payload->partner_key = htons(port_info.partner_key_val);
                lacpdu_payload->partner_port_priority = htons(static_cast<uint16_t>((port_info.partner_port_id_val >> 16) & 0xFFFF)); // Assuming port_id_val upper is prio
                lacpdu_payload->partner_port_number = htons(static_cast<uint16_t>(port_info.partner_port_id_val & 0xFFFF)); // Assuming port_id_val lower is num
                lacpdu_payload->partner_state = port_info.partner_state_val;
            } else {
                // Default/zero partner info is already set by Lacpdu constructor
            }

            // Collector Information
            // collector_max_delay: default 0, can be configured. For now, use default.
            lacpdu_payload->collector_max_delay = htons(0); // Default, no specific configuration for it yet

            // TLV types, lengths, terminator already set by Lacpdu constructor.

            Packet pkt(pb);
            // Packet length is already set by pb->set_data_len(buffer_size)
            lacpdus_to_send.push_back(std::move(pkt));

            if (logger_) logger_->info("LACP", "Generated LACPDU for port " + std::to_string(port_id));

            // Transition state out of PERIODIC_TX to prevent immediate re-send,
            // unless timer logic handles this. Typically, after sending, the state
            // would change or a timer reset. For now, let's assume the periodic timer handler
            // will transition it back to PERIODIC_TX when appropriate.
            // Or, more simply, reset it here if it's a one-shot send per trigger.
            // For now, let periodic_tx_machine handle state transitions.
            // port_info.periodic_tx_state = LacpPortInfo::PeriodicTxState::SLOW_PERIODIC; // Example
        }
    }
    return lacpdus_to_send;
}

void LacpManager::run_lacp_timers_and_statemachines() {
    if (logger_) logger_->debug("LACP", "Run LACP Timers and State Machines - START");

    // Iterate using an iterator to allow modification of LacpPortInfo objects
    for (auto it = port_lacp_info_.begin(); it != port_lacp_info_.end(); ++it) {
        uint32_t port_id = it->first;
        LacpPortInfo& port_info = it->second;

        // if (logger_) logger_->trace("LACP", "Processing timers and SM for port " + std::to_string(port_id));

        // --- Timer Management ---
        // Current While Timer (Rx Machine)
        if (port_info.current_while_timer_ticks > 0) {
            port_info.current_while_timer_ticks--;
            if (port_info.current_while_timer_ticks == 0) {
                port_info.current_while_timer_expired_event = true;
                if (logger_) logger_->debug("LACP", "Port " + std::to_string(port_id) + ": Current While Timer EXPIRED.");
            }
        }

        // Short Timeout Timer (Periodic Tx Machine)
        if (port_info.short_timeout_timer_ticks > 0) {
            port_info.short_timeout_timer_ticks--;
            if (port_info.short_timeout_timer_ticks == 0) {
                port_info.short_timeout_timer_expired_event = true;
                if (logger_) logger_->debug("LACP", "Port " + std::to_string(port_id) + ": Short Timeout Timer EXPIRED.");
            }
        }

        // Long Timeout Timer (Periodic Tx Machine)
        if (port_info.long_timeout_timer_ticks > 0) {
            port_info.long_timeout_timer_ticks--;
            if (port_info.long_timeout_timer_ticks == 0) {
                port_info.long_timeout_timer_expired_event = true;
                if (logger_) logger_->debug("LACP", "Port " + std::to_string(port_id) + ": Long Timeout Timer EXPIRED.");
            }
        }

        // Aggregate Wait While Timer (Mux Machine)
        if (port_info.current_wait_while_timer_ticks > 0) {
            port_info.current_wait_while_timer_ticks--;
            if (port_info.current_wait_while_timer_ticks == 0) {
                port_info.wait_while_timer_expired_event = true;
                if (logger_) logger_->debug("LACP", "Port " + std::to_string(port_id) + ": Aggregate Wait While Timer EXPIRED.");
            }
        }

        // --- State Machine Execution ---
        // Note: port_info.port_enabled and port_info.lacp_enabled should be updated by an external entity (e.g. InterfaceManager)
        // before this function is called. The state machines will react to these flags.

        // 1. Selection Logic (Simplified: updates port_info.selected_for_aggregation)
        // This was already called within run_lacp_mux_machine, but calling it here ensures it's fresh
        // before any state machine that might depend on selection runs.
        // update_port_selection_status(port_id, port_info); // Already called in Mux

        // 2. Run Rx State Machine
        run_lacp_rx_machine(port_id);
        // Rx machine consumes current_while_timer_expired_event and pdu_received_event.
        // process_lacpdu sets pdu_received_event. Rx machine clears it.
        // Timer logic above sets current_while_timer_expired_event. Rx machine clears it.
        // So, no explicit reset of these two flags is needed here IF RxMachine handles them.
        // However, the prompt implies resetting after the call. Let's stick to that for safety,
        // assuming the SM might not clear it in all paths or if it's not consumed.
        // port_info.current_while_timer_expired_event = false; // Already consumed by RxMachine if it acted on it.
        // port_info.pdu_received_event = false; // Also consumed by RxMachine.

        // 3. Run Periodic Tx State Machine
        run_lacp_periodic_tx_machine(port_id);
        // Periodic Tx machine consumes short_timeout_timer_expired_event and long_timeout_timer_expired_event.
        // port_info.short_timeout_timer_expired_event = false; // Consumed by PeriodicTxMachine
        // port_info.long_timeout_timer_expired_event = false;  // Consumed by PeriodicTxMachine

        // 4. Run Mux State Machine
        // Mux machine calls update_port_selection_status internally.
        run_lacp_mux_machine(port_id);
        // Mux machine consumes wait_while_timer_expired_event.
        // port_info.wait_while_timer_expired_event = false; // Consumed by MuxMachine
    }
    if (logger_) logger_->debug("LACP", "Run LACP Timers and State Machines - END");
}
void LacpManager::initialize_lacp_port_info(uint32_t port_id, const LagConfig& lag_config) {
    if (logger_) logger_->debug("LACP", "Initializing LACP port info for port " + std::to_string(port_id) +
                                       " for LAG " + std::to_string(lag_config.lag_id));

    // Retrieve or Create PortInfo
    // emplace returns a pair, where .first is an iterator to the element and .second is a bool indicating success.
    // If the element already exists, .first points to the existing element and .second is false.
    auto emplace_result = port_lacp_info_.emplace(port_id, LacpPortInfo(port_id));
    LacpPortInfo& port_info = emplace_result.first->second;

    // If emplace_result.second is false, it means the port_id already existed.
    // We should still re-initialize it based on the provided lag_config.
    // The LacpPortInfo constructor LacpPortInfo(port_id) already sets port_id_physical
    // and some defaults. We will now override/set specific LACP parameters.

    // Set Actor Information
    port_info.actor_system_id_val = actor_system_id_; // Global switch system ID
    // Port priority is from port_info itself (default 128 or previously set).
    // Port ID is the physical port_id.
    port_info.actor_port_id_val = (static_cast<uint32_t>(port_info.port_priority_val) << 16) | port_id;
    port_info.actor_key_val = lag_config.actor_admin_key;

    // Initialize actor_state_val
    port_info.actor_state_val = 0; // Start fresh
    if (lag_config.active_mode) {
        port_info.set_actor_state_flag(LacpStateFlag::LACP_ACTIVITY, true);
    } else {
        port_info.set_actor_state_flag(LacpStateFlag::LACP_ACTIVITY, false);
    }

    if (lag_config.lacp_rate == 1) { // 1 = fast (short timeout)
        port_info.set_actor_state_flag(LacpStateFlag::LACP_TIMEOUT, true);
    } else { // 0 = slow (long timeout)
        port_info.set_actor_state_flag(LacpStateFlag::LACP_TIMEOUT, false);
    }

    port_info.set_actor_state_flag(LacpStateFlag::AGGREGATION, true); // Port can aggregate
    port_info.set_actor_state_flag(LacpStateFlag::SYNCHRONIZATION, false); // Not yet synchronized
    port_info.set_actor_state_flag(LacpStateFlag::COLLECTING, false);
    port_info.set_actor_state_flag(LacpStateFlag::DISTRIBUTING, false);
    port_info.set_actor_state_flag(LacpStateFlag::DEFAULTED, true); // Parameters are administratively configured
    port_info.set_actor_state_flag(LacpStateFlag::EXPIRED, false);

    // Set Partner Information (Initial Defaults)
    port_info.partner_system_id_val = 0;
    port_info.partner_port_id_val = 0;
    port_info.partner_key_val = 0;

    port_info.partner_state_val = 0; // Start fresh for partner state
    port_info.set_actor_state_flag(LacpStateFlag::LACP_ACTIVITY, false); // Assuming passive partner initially for partner_state
                                                                      // This is actually setting on actor_state, needs fix.
                                                                      // Corrected below for partner_state_val directly.
    // Correctly initialize partner_state_val:
    port_info.partner_state_val = 0; // Reset
    // Typically, initial partner state has DEFAULTED and EXPIRED set.
    // LACP_ACTIVITY and LACP_TIMEOUT for partner are learned, so start them as 0 or reflecting a passive/long state.
    // Let's follow the initial constructor logic for partner_state from LacpPortInfo:
    port_info.partner_state_val = LacpStateFlag::DEFAULTED | LacpStateFlag::EXPIRED;
    // The other flags (LACP_ACTIVITY, LACP_TIMEOUT, AGGREGATION, SYNCHRONIZATION, COLLECTING, DISTRIBUTING)
    // for the partner will be learned from incoming PDUs. So, their initial value of 0 (unset) is appropriate.


    // Reset Timers (tick counts)
    port_info.current_while_timer_ticks = 0;
    port_info.short_timeout_timer_ticks = 0;
    port_info.long_timeout_timer_ticks = 0;

    // Reset State Machines
    port_info.mux_state = LacpPortInfo::MuxMachineState::DETACHED;
    port_info.rx_state = LacpPortInfo::RxMachineState::INITIALIZE; // Will transition based on port status
    port_info.periodic_tx_state = LacpPortInfo::PeriodicTxState::NO_PERIODIC;

    // Port Aggregation Status
    port_info.is_active_member_of_lag = false;
    port_info.current_aggregator_id = 0; // Will be set by selection logic

    // Ensure port_to_lag_map_ is updated. This is typically done by the caller (create_lag/add_port_to_lag)
    // but double-checking or ensuring consistency is good.
    // port_to_lag_map_[port_id] = lag_config.lag_id; // This line is already in create_lag and add_port_to_lag

    if (logger_) {
        logger_->info("LACP", "Port " + std::to_string(port_id) + " initialized with Actor Key: " +
                               std::to_string(port_info.actor_key_val) + ", Actor State: 0x" +
                               std::to_string(port_info.actor_state_val) + // Needs hex for state
                               ", Partner State: 0x" + std::to_string(port_info.partner_state_val)); // Needs hex for state
    }
}
void LacpManager::run_lacp_rx_machine(uint32_t port_id) {
    auto port_info_it = port_lacp_info_.find(port_id);
    if (port_info_it == port_lacp_info_.end()) {
        if (logger_) logger_->error("LACP", "RxMachine: Port " + std::to_string(port_id) + " not found in port_lacp_info_.");
        return;
    }
    LacpPortInfo& port_info = port_info_it->second;
    LacpPortInfo::RxMachineState current_state_for_log = port_info.rx_state; // For logging transition

    // Retrieve associated LagConfig, needed for some decisions (e.g. admin partner values, though not used yet)
    auto lag_id_opt = get_lag_for_port(port_id);
    std::optional<LagConfig> lag_config_opt;
    if(lag_id_opt.has_value()) {
        lag_config_opt = get_lag_config(lag_id_opt.value());
    }
    // If no LAG config, some operations might need defaults or error handling.
    // For now, assume lag_config_opt will be present if port is LACP enabled.


    // Check external conditions once at the beginning
    // These would ideally be fetched from an InterfaceManager or similar.
    // For now, using the flags in LacpPortInfo which should be updated by management plane.
    bool port_physically_enabled = port_info.port_enabled; // Assumed to be updated elsewhere
    bool lacp_protocol_enabled = port_info.lacp_enabled; // Assumed to be updated elsewhere


    switch (port_info.rx_state) {
        case LacpPortInfo::RxMachineState::INITIALIZE:
            // This state is typically entered once.
            // Set partner to passive, long timeout, not agg, not sync, defaulted, expired.
            port_info.partner_state_val = 0;
            port_info.set_partner_state_flag(LacpStateFlag::LACP_ACTIVITY, false);
            port_info.set_partner_state_flag(LacpStateFlag::LACP_TIMEOUT, false); // Long timeout
            port_info.set_partner_state_flag(LacpStateFlag::AGGREGATION, false);
            port_info.set_partner_state_flag(LacpStateFlag::SYNCHRONIZATION, false);
            port_info.set_partner_state_flag(LacpStateFlag::COLLECTING, false);
            port_info.set_partner_state_flag(LacpStateFlag::DISTRIBUTING, false);
            port_info.set_partner_state_flag(LacpStateFlag::DEFAULTED, true);
            port_info.set_partner_state_flag(LacpStateFlag::EXPIRED, true);

            port_info.partner_system_id_val = 0;
            port_info.partner_port_id_val = 0;
            port_info.partner_key_val = 0;

            port_info.set_actor_state_flag(LacpStateFlag::EXPIRED, false); // Actor's own state is not expired
            port_info.rx_state = LacpPortInfo::RxMachineState::PORT_DISABLED;
            break;

        case LacpPortInfo::RxMachineState::PORT_DISABLED:
            if (!port_physically_enabled || !lacp_protocol_enabled) {
                // Remain in this state or go to LACP_DISABLED if appropriate
                // The standard suggests: port_moved and !lacp_enabled leads to LACP_DISABLED
                // and begin leads to PORT_DISABLED. If !port_enabled, it should stay here.
                // For now, if lacp becomes disabled, go to LACP_DISABLED state.
                if (!lacp_protocol_enabled && port_physically_enabled) { // LACP specifically disabled
                     port_info.rx_state = LacpPortInfo::RxMachineState::LACP_DISABLED;
                } else { // Port itself is down, or both down.
                    // Action: record defaulted partner, actor expired = false
                    // This seems to be covered by LACP_DISABLED actions as per diagram.
                    // Let's ensure partner is defaulted.
                    record_defaulted_partner(port_info); // Resets partner, sets EXPIRED and DEFAULTED
                    port_info.set_actor_state_flag(LacpStateFlag::EXPIRED, false);
                    port_info.current_while_timer_ticks = 0; // Stop timer
                }
            } else { // Port enabled and LACP enabled
                port_info.rx_state = LacpPortInfo::RxMachineState::EXPIRED;
            }
            break;

        case LacpPortInfo::RxMachineState::LACP_DISABLED:
            // Actions in LACP_DISABLED state
            record_defaulted_partner(port_info);
            port_info.set_actor_state_flag(LacpStateFlag::EXPIRED, false);
            port_info.current_while_timer_ticks = 0; // Stop timer

            if (port_physically_enabled && lacp_protocol_enabled) { // LACP becomes re-enabled
                port_info.rx_state = LacpPortInfo::RxMachineState::EXPIRED;
            }
            // Else, stay in LACP_DISABLED
            break;

        case LacpPortInfo::RxMachineState::EXPIRED:
            port_info.set_partner_state_flag(LacpStateFlag::SYNCHRONIZATION, false);
            port_info.set_partner_state_flag(LacpStateFlag::EXPIRED, true);
            port_info.current_while_timer_ticks = 0; // Stop timer (timer already expired to get here or was stopped)

            if (port_info.pdu_received_event) {
                port_info.pdu_received_event = false; // Consume event
                update_ntt(port_info);
                record_pdu_partner_info(port_info); // Uses last_received_pdu_actor_info
                // Set timer based on LACP_TIMEOUT flag from partner's state (now in port_info.partner_state_val)
                set_current_while_timer(port_info, port_info.get_partner_state_flag(LacpStateFlag::LACP_TIMEOUT));
                port_info.set_actor_state_flag(LacpStateFlag::EXPIRED, false); // Our info is current from partner's view
                port_info.rx_state = LacpPortInfo::RxMachineState::CURRENT;
            } else if (!port_physically_enabled || !lacp_protocol_enabled) {
                port_info.rx_state = LacpPortInfo::RxMachineState::PORT_DISABLED;
            }
            // Else, stay in EXPIRED
            break;

        case LacpPortInfo::RxMachineState::DEFAULTED:
            if (!lag_config_opt.has_value()) {
                 if(logger_) logger_->error("LACP", "RxMachine: Port " + std::to_string(port_id) + " in DEFAULTED state but no LAG config found.");
                 record_defaulted_partner(port_info); // Fallback to system defaults
            } else {
                 update_default_selected_partner_info(port_info, lag_config_opt.value());
            }
            port_info.set_partner_state_flag(LacpStateFlag::EXPIRED, false); // Per state diagram for DEFAULTED

            if (port_info.pdu_received_event) {
                port_info.pdu_received_event = false; // Consume event
                update_ntt(port_info);
                record_pdu_partner_info(port_info);
                set_current_while_timer(port_info, port_info.get_partner_state_flag(LacpStateFlag::LACP_TIMEOUT));
                port_info.rx_state = LacpPortInfo::RxMachineState::CURRENT;
            } else if (!port_physically_enabled || !lacp_protocol_enabled) {
                port_info.rx_state = LacpPortInfo::RxMachineState::PORT_DISABLED;
            }
            // Else, stay in DEFAULTED
            break;

        case LacpPortInfo::RxMachineState::CURRENT:
            if (port_info.current_while_timer_expired_event) {
                port_info.current_while_timer_expired_event = false; // Consume event
                record_defaulted_partner(port_info); // This sets EXPIRED = true for partner
                // port_info.set_partner_state_flag(LacpStateFlag::EXPIRED, true); // Redundant due to above
                port_info.rx_state = LacpPortInfo::RxMachineState::EXPIRED;
            } else if (port_info.pdu_received_event) {
                port_info.pdu_received_event = false; // Consume event
                update_ntt(port_info);
                // Compare PDU's actor info (stored in last_received_pdu_actor_info) with current partner info
                if (compare_pdu_with_partner_info(port_info.last_received_pdu_actor_info, port_info)) {
                    record_pdu_partner_info(port_info); // Updates partner info from last_received_pdu_actor_info
                }
                // Reset timer based on (potentially updated) partner's LACP_TIMEOUT state
                set_current_while_timer(port_info, port_info.get_partner_state_flag(LacpStateFlag::LACP_TIMEOUT));
            } else if (!port_physically_enabled || !lacp_protocol_enabled) {
                record_defaulted_partner(port_info); // Transition to PORT_DISABLED implies partner is lost/defaulted
                port_info.rx_state = LacpPortInfo::RxMachineState::PORT_DISABLED;
            }
            // Else, stay in CURRENT
            break;
    }

    if (logger_ && port_info.rx_state != current_state_for_log) {
        logger_->info("LACP", "Port " + std::to_string(port_id) + ": RxMachine transitioned from " +
                               // TODO: Convert enum to string for logging
                               std::to_string(static_cast<int>(current_state_for_log)) + " to " +
                               std::to_string(static_cast<int>(port_info.rx_state)));
    }

    // Ensure pdu_received_event is consumed if not explicitly handled by a transition
    // This is important if a state doesn't have a direct transition on pdu_received_event
    // but the event occurred. However, standard state machine implies events are only consumed on transitions.
    // For safety, if it's still true and wasn't used, perhaps log or clear.
    if(port_info.pdu_received_event && logger_){
        logger_->debug("LACP", "Port " + std::to_string(port_id) + ": pdu_received_event was set but not consumed by RxMachine state " + std::to_string(static_cast<int>(port_info.rx_state)));
        // port_info.pdu_received_event = false; // Optionally clear if it should always be consumed per call
    }

}

// --- Helper function definitions for RxMachine ---

void LacpManager::record_defaulted_partner(LacpPortInfo& port_info) {
    if (logger_) logger_->debug("LACP", "Port " + std::to_string(port_info.port_id_physical) + ": Recording defaulted partner.");
    port_info.partner_system_id_val = 0; // Or some admin default if specified
    port_info.partner_port_id_val = 0;   // Or some admin default
    port_info.partner_key_val = 0;       // Or some admin default

    port_info.partner_state_val = 0; // Clear previous state
    port_info.set_partner_state_flag(LacpStateFlag::LACP_ACTIVITY, false); // Typically passive for default
    port_info.set_partner_state_flag(LacpStateFlag::LACP_TIMEOUT, false);  // Long timeout
    port_info.set_partner_state_flag(LacpStateFlag::AGGREGATION, false);   // Cannot aggregate with default
    port_info.set_partner_state_flag(LacpStateFlag::SYNCHRONIZATION, false);
    port_info.set_partner_state_flag(LacpStateFlag::COLLECTING, false);
    port_info.set_partner_state_flag(LacpStateFlag::DISTRIBUTING, false);
    port_info.set_partner_state_flag(LacpStateFlag::DEFAULTED, true);
    port_info.set_partner_state_flag(LacpStateFlag::EXPIRED, true); // Defaulted partner info is also considered stale/expired
}

void LacpManager::record_pdu_partner_info(LacpPortInfo& port_info) {
    if (!port_info.last_received_pdu_actor_info.valid) {
        if (logger_) logger_->warning("LACP", "Port " + std::to_string(port_info.port_id_physical) + ": Attempted to record PDU partner info, but no valid PDU data stored.");
        return;
    }
    if (logger_) logger_->debug("LACP", "Port " + std::to_string(port_info.port_id_physical) + ": Recording partner info from PDU.");

    port_info.partner_system_id_val = port_info.last_received_pdu_actor_info.system_id;
    port_info.partner_key_val = port_info.last_received_pdu_actor_info.key;
    port_info.partner_port_id_val = (static_cast<uint32_t>(port_info.last_received_pdu_actor_info.port_priority) << 16) |
                                     port_info.last_received_pdu_actor_info.port_number;
    port_info.partner_state_val = port_info.last_received_pdu_actor_info.state;

    // After recording from PDU, the partner info is no longer considered defaulted or expired (until timer hits)
    port_info.set_partner_state_flag(LacpStateFlag::DEFAULTED, false);
    port_info.set_partner_state_flag(LacpStateFlag::EXPIRED, false);

    // The PDU data has been consumed for this event.
    port_info.last_received_pdu_actor_info.valid = false;
}

// This might be similar to record_defaulted_partner, but specifically for when DEFAULTED state is entered.
// The standard implies using administratively configured default values for the partner.
// For now, it's the same as record_defaulted_partner.
void LacpManager::update_default_selected_partner_info(LacpPortInfo& port_info, const LagConfig& lag_config) {
    if (logger_) logger_->debug("LACP", "Port " + std::to_string(port_info.port_id_physical) + ": Updating default selected partner info.");
    // For now, this is the same as setting a fully defaulted partner.
    // IEEE 802.1AX section 5.4.10 (Receive Machine) mentions using administrative values.
    // If LagConfig had specific admin values for expected partner, they would be used here.
    record_defaulted_partner(port_info);
    // Additionally, ensure EXPIRED is false as per state diagram for DEFAULTED state.
    port_info.set_partner_state_flag(LacpStateFlag::EXPIRED, false);
}

bool LacpManager::compare_pdu_with_partner_info(const LacpPortInfo::PduActorInfo& pdu_actor_info, const LacpPortInfo& port_info) {
    if (!pdu_actor_info.valid) return false; // No new PDU to compare

    uint32_t pdu_partner_port_id = (static_cast<uint32_t>(pdu_actor_info.port_priority) << 16) | pdu_actor_info.port_number;

    bool changed = (pdu_actor_info.system_id != port_info.partner_system_id_val ||
                    pdu_actor_info.key != port_info.partner_key_val ||
                    pdu_partner_port_id != port_info.partner_port_id_val || // Note: partner_port_id_val is already combined
                    pdu_actor_info.state != port_info.partner_state_val);
    if (logger_ && changed) {
        logger_->debug("LACP", "Port " + std::to_string(port_info.port_id_physical) + ": PDU info differs from current partner info.");
    }
    return changed;
}

void LacpManager::set_current_while_timer(LacpPortInfo& port_info, bool is_short_timeout) {
    port_info.current_while_timer_ticks = is_short_timeout ? SHORT_TIMEOUT_TICKS : LONG_TIMEOUT_TICKS;
    if (logger_) logger_->debug("LACP", "Port " + std::to_string(port_info.port_id_physical) +
                                       ": Current While Timer set to " + std::to_string(port_info.current_while_timer_ticks) + " ticks.");
}

void LacpManager::update_ntt(LacpPortInfo& port_info) {
    port_info.ntt_event = true;
    if (logger_) logger_->debug("LACP", "Port " + std::to_string(port_info.port_id_physical) + ": NTT flag set.");
}

// Method implementations for LacpPortInfo state flags
void LacpPortInfo::set_partner_state_flag(LacpStateFlag flag, bool set) {
    if (set) partner_state_val |= static_cast<uint8_t>(flag);
    else partner_state_val &= ~static_cast<uint8_t>(flag);
}

bool LacpPortInfo::get_partner_state_flag(LacpStateFlag flag) const {
    return (partner_state_val & static_cast<uint8_t>(flag)) != 0;
}


// --- Helper function for PeriodicTxMachine ---
bool LacpManager::partner_is_short_timeout(const LacpPortInfo& port_info) {
    // Partner desires short timeout if their LACP_TIMEOUT flag is set.
    // We also need to consider our own timeout preference.
    // The standard (IEEE 802.1AX-2014 section 43.4.12 - Periodic Transmission machine variables)
    // refers to partner_oper_port_state.LACP_Timeout.
    // If the partner's LACP_TIMEOUT flag is set, they want fast.
    // The decision to run fast or slow also depends on our own configuration (actor_state_val's LACP_TIMEOUT).
    // This helper is specifically for checking the *partner's* desire.
    // The state machine logic then combines this with local config/state.
    // A common interpretation: if partner wants short, we should try to match if we also support short.
    // For the direct check required by the state diagram:
    // "partner_oper_port_state.LACP_Timeout"
    return port_info.get_partner_state_flag(LacpStateFlag::LACP_TIMEOUT);
}


// --- LacpManager::run_lacp_periodic_tx_machine ---
void LacpManager::run_lacp_periodic_tx_machine(uint32_t port_id) {
    auto port_info_it = port_lacp_info_.find(port_id);
    if (port_info_it == port_lacp_info_.end()) {
        if (logger_) logger_->error("LACP", "PeriodicTxMachine: Port " + std::to_string(port_id) + " not found.");
        return;
    }
    LacpPortInfo& port_info = port_info_it->second;
    LacpPortInfo::PeriodicTxState current_tx_state_for_log = port_info.periodic_tx_state;

    // Actions executed at the beginning of each state or on transition
    // Helper lambdas for starting/stopping timers might be cleaner if complex,
    // but direct manipulation is fine for now.
    auto start_short_timeout_timer = [&]() {
        port_info.short_timeout_timer_ticks = SHORT_TIMEOUT_TICKS;
        port_info.short_timeout_timer_expired_event = false;
        if (logger_) logger_->debug("LACP", "Port " + std::to_string(port_id) + ": Short timeout timer started (" + std::to_string(SHORT_TIMEOUT_TICKS) + " ticks).");
    };
    auto stop_short_timeout_timer = [&]() {
        port_info.short_timeout_timer_ticks = 0;
        port_info.short_timeout_timer_expired_event = false;
    };
     auto start_long_timeout_timer = [&]() {
        port_info.long_timeout_timer_ticks = LONG_TIMEOUT_TICKS;
        port_info.long_timeout_timer_expired_event = false;
        if (logger_) logger_->debug("LACP", "Port " + std::to_string(port_id) + ": Long timeout timer started (" + std::to_string(LONG_TIMEOUT_TICKS) + " ticks).");
    };
    auto stop_long_timeout_timer = [&]() {
        port_info.long_timeout_timer_ticks = 0;
        port_info.long_timeout_timer_expired_event = false;
    };


    switch (port_info.periodic_tx_state) {
        case LacpPortInfo::PeriodicTxState::NO_PERIODIC:
            if (port_info.ntt_event ||
                (port_info.lacp_enabled && port_info.port_enabled &&
                 (port_info.get_actor_state_flag(LacpStateFlag::LACP_ACTIVITY) ||
                  port_info.get_partner_state_flag(LacpStateFlag::LACP_ACTIVITY)))) {

                port_info.periodic_tx_state = LacpPortInfo::PeriodicTxState::FAST_PERIODIC;
                start_short_timeout_timer();
                // ntt_event is consumed by generate_lacpdus, not cleared here directly unless specified
            }
            break;

        case LacpPortInfo::PeriodicTxState::FAST_PERIODIC:
            if (!port_info.lacp_enabled || !port_info.port_enabled ||
                (!port_info.get_actor_state_flag(LacpStateFlag::LACP_ACTIVITY) &&
                 !port_info.get_partner_state_flag(LacpStateFlag::LACP_ACTIVITY))) {

                port_info.periodic_tx_state = LacpPortInfo::PeriodicTxState::NO_PERIODIC;
                stop_short_timeout_timer();
                stop_long_timeout_timer(); // Ensure both are stopped
            } else if (port_info.short_timeout_timer_expired_event) {
                port_info.short_timeout_timer_expired_event = false; // Consume event
                port_info.periodic_tx_state = LacpPortInfo::PeriodicTxState::PERIODIC_TX;
                // Action for PERIODIC_TX will set ntt_event = true
            } else if (!partner_is_short_timeout(port_info) && !port_info.get_actor_state_flag(LacpStateFlag::LACP_TIMEOUT)) {
                // Transition to SLOW_PERIODIC if partner is not short timeout AND we are not short timeout
                // The standard implies if partner is long, we can go slow.
                // If actor is short timeout, it implies we want to send fast regardless of partner.
                // A more precise condition might be:
                // if (!port_info.get_actor_state_flag(LacpStateFlag::LACP_TIMEOUT) && !partner_is_short_timeout(port_info))
                // For now, using the simpler: if partner is not short, consider slow.
                // However, if actor is configured for fast, it should stay fast.
                // So, only go slow if actor is also configured for slow AND partner is slow.
                // Standard: "ELSE IF (Actor_Oper_Port_State.LACP_Timeout == Long_Timeout) AND
                // (Partner_Oper_Port_State.LACP_Timeout == Long_Timeout)" -> go to SLOW.
                // Simplified: If this actor is set to long timeout, and partner is also long, then go slow.
                // If actor is short, it stays fast. If actor is long, but partner is short, it should also stay fast.
                // So transition to SLOW only if actor is long AND partner is long.
                // The condition `!partner_is_short_timeout(port_info)` means partner is long.
                // We also need to check if actor is long: `!port_info.get_actor_state_flag(LacpStateFlag::LACP_TIMEOUT)`
                if (!port_info.get_actor_state_flag(LacpStateFlag::LACP_TIMEOUT) && !partner_is_short_timeout(port_info) ) {
                    port_info.periodic_tx_state = LacpPortInfo::PeriodicTxState::SLOW_PERIODIC;
                    stop_short_timeout_timer();
                    start_long_timeout_timer();
                }
                // If actor is short timeout, it will remain in FAST_PERIODIC.
                // If actor is long timeout but partner is short timeout, it also remains FAST_PERIODIC.
            }
            break;

        case LacpPortInfo::PeriodicTxState::SLOW_PERIODIC:
            if (!port_info.lacp_enabled || !port_info.port_enabled ||
                (!port_info.get_actor_state_flag(LacpStateFlag::LACP_ACTIVITY) &&
                 !port_info.get_partner_state_flag(LacpStateFlag::LACP_ACTIVITY))) {

                port_info.periodic_tx_state = LacpPortInfo::PeriodicTxState::NO_PERIODIC;
                stop_short_timeout_timer(); // Ensure both are stopped
                stop_long_timeout_timer();
            } else if (port_info.long_timeout_timer_expired_event) {
                port_info.long_timeout_timer_expired_event = false; // Consume event
                port_info.periodic_tx_state = LacpPortInfo::PeriodicTxState::PERIODIC_TX;
            } else if (partner_is_short_timeout(port_info) || port_info.get_actor_state_flag(LacpStateFlag::LACP_TIMEOUT)) {
                // If partner wants short OR we are configured for short timeout, go fast.
                // Standard: "(Actor_Oper_Port_State.LACP_Timeout == Short_Timeout) OR
                // (Partner_Oper_Port_State.LACP_Timeout == Short_Timeout)"
                port_info.periodic_tx_state = LacpPortInfo::PeriodicTxState::FAST_PERIODIC;
                stop_long_timeout_timer();
                start_short_timeout_timer();
            }
            break;

        case LacpPortInfo::PeriodicTxState::PERIODIC_TX:
            // Action on entry:
            port_info.ntt_event = true; // Signal generate_lacpdus
            if (logger_) logger_->debug("LACP", "Port " + std::to_string(port_id) + ": PERIODIC_TX setting ntt_event=true.");


            // Transitions out of PERIODIC_TX:
            // This state is transient. It sets NTT and immediately decides the next periodic interval.
            // The choice depends on actor's and partner's timeout states.
            // If Actor is Short_Timeout OR Partner is Short_Timeout, next state is FAST.
            // Else (Actor is Long_Timeout AND Partner is Long_Timeout), next state is SLOW.
            if (port_info.get_actor_state_flag(LacpStateFlag::LACP_TIMEOUT) || partner_is_short_timeout(port_info)) {
                port_info.periodic_tx_state = LacpPortInfo::PeriodicTxState::FAST_PERIODIC;
                start_short_timeout_timer(); // Restart appropriate timer for the new state
            } else {
                port_info.periodic_tx_state = LacpPortInfo::PeriodicTxState::SLOW_PERIODIC;
                start_long_timeout_timer(); // Restart appropriate timer
            }
            break;
    }

    if (logger_ && port_info.periodic_tx_state != current_tx_state_for_log) {
         logger_->info("LACP", "Port " + std::to_string(port_id) + ": PeriodicTxMachine transitioned from " +
                               std::to_string(static_cast<int>(current_tx_state_for_log)) + " to " + // TODO: Enum to string
                               std::to_string(static_cast<int>(port_info.periodic_tx_state)));
    }
}

void LacpManager::update_port_selection_logic(uint32_t port_id_changed) {
    if (logger_) logger_->debug("LACP", "Updating port selection logic due to port " + std::to_string(port_id_changed) + " state change.");

    auto port_info_iter = port_lacp_info_.find(port_id_changed);
    if (port_info_iter == port_lacp_info_.end()) {
        if (logger_) logger_->error("LACP", "update_port_selection_logic: Port " + std::to_string(port_id_changed) + " not found in port_lacp_info_.");
        return;
    }
    // LacpPortInfo& changed_port_info = port_info_iter->second; // Not directly used, but good to have

    auto lag_id_opt = get_lag_for_port(port_id_changed);
    if (!lag_id_opt) {
        // This can happen if a port is removed from a LAG.
        // In this case, there's no LAG to update active members for based on this port.
        // If the port was part of a LAG that still exists, that LAG's active member list
        // would be updated when another of its members changes state, or periodically.
        // For now, if the changed port is no longer in a LAG, we don't update any specific LAG here.
        if (logger_) logger_->debug("LACP", "update_port_selection_logic: Port " + std::to_string(port_id_changed) + " is not currently part of any LAG.");
        return;
    }
    uint32_t lag_id = lag_id_opt.value();

    auto lag_cfg_iter = lags_.find(lag_id);
    if (lag_cfg_iter == lags_.end()) {
        if (logger_) logger_->error("LACP", "update_port_selection_logic: LAG ID " + std::to_string(lag_id) + " not found in lags_ map for port " + std::to_string(port_id_changed) + ".");
        return;
    }
    LagConfig& lag_config = lag_cfg_iter->second;

    if (logger_) logger_->debug("LACP", "Rebuilding active_distributing_members for LAG " + std::to_string(lag_id));

    lag_config.active_distributing_members.clear();
    for (uint32_t member_port_id : lag_config.member_ports) {
        auto member_port_info_iter = port_lacp_info_.find(member_port_id);
        if (member_port_info_iter != port_lacp_info_.end()) {
            const LacpPortInfo& member_port_info = member_port_info_iter->second;
            // A port is actively distributing if its Mux machine is in COLLECTING_DISTRIBUTING state
            // AND it has the DISTRIBUTING flag set in its actor state.
            // The Mux machine sets COLLECTING and DISTRIBUTING flags on actor_state_val
            // when entering COLLECTING_DISTRIBUTING state.
            if (member_port_info.mux_state == LacpPortInfo::MuxMachineState::COLLECTING_DISTRIBUTING &&
                member_port_info.get_actor_state_flag(LacpStateFlag::DISTRIBUTING) &&
                member_port_info.get_actor_state_flag(LacpStateFlag::COLLECTING)) {
                lag_config.active_distributing_members.push_back(member_port_id);
            }
        } else {
            if (logger_) logger_->warning("LACP", "update_port_selection_logic: Port " + std::to_string(member_port_id) +
                                                 " (member of LAG " + std::to_string(lag_id) + ") not found in port_lacp_info_.");
        }
    }

    // Sort for consistent hashing, if the hashing algorithm relies on order.
    std::sort(lag_config.active_distributing_members.begin(), lag_config.active_distributing_members.end());

    if (logger_) {
        std::string active_members_str;
        for (size_t i = 0; i < lag_config.active_distributing_members.size(); ++i) {
            active_members_str += std::to_string(lag_config.active_distributing_members[i]);
            if (i < lag_config.active_distributing_members.size() - 1) {
                active_members_str += ", ";
            }
        }
        logger_->info("LACP", "LAG " + std::to_string(lag_id) + " active distributing members updated: [" + active_members_str + "]");
    }
}

// --- Helper functions for MuxMachine ---

void LacpManager::detach_mux_from_aggregator(uint32_t port_id, LacpPortInfo& port_info) {
    if (logger_) logger_->debug("LACP", "Port " + std::to_string(port_id) + ": Detaching MUX from aggregator.");
    port_info.current_aggregator_id = 0; // No longer associated with a specific aggregator
    port_info.is_active_member_of_lag = false;
    // Call the more general update_port_selection_logic, which might update LAG-wide active port lists
    update_port_selection_logic(port_id);
}

void LacpManager::attach_mux_to_aggregator(uint32_t port_id, LacpPortInfo& port_info) {
    if (logger_) logger_->debug("LACP", "Port " + std::to_string(port_id) + ": Attaching MUX to aggregator.");
    auto lag_id_opt = get_lag_for_port(port_id);
    if (lag_id_opt) {
        port_info.current_aggregator_id = lag_id_opt.value(); // Associated with its LAG ID
        // is_active_member_of_lag will be true when COLLECTING and DISTRIBUTING are set.
    } else {
        if (logger_) logger_->error("LACP", "Port " + std::to_string(port_id) + ": Cannot attach MUX, port not mapped to any LAG.");
        port_info.current_aggregator_id = 0; // Should not happen if selection logic is correct
    }
    update_port_selection_logic(port_id);
}

void LacpManager::disable_collecting_distributing(LacpPortInfo& port_info) {
    bool changed = false;
    if (port_info.get_actor_state_flag(LacpStateFlag::COLLECTING)) {
        port_info.set_actor_state_flag(LacpStateFlag::COLLECTING, false);
        changed = true;
    }
    if (port_info.get_actor_state_flag(LacpStateFlag::DISTRIBUTING)) {
        port_info.set_actor_state_flag(LacpStateFlag::DISTRIBUTING, false);
        changed = true;
    }
    if (changed && logger_) {
        logger_->debug("LACP", "Port " + std::to_string(port_info.port_id_physical) + ": Collecting/Distributing disabled. Actor state: 0x" + std::to_string(port_info.actor_state_val));
    }
    if(changed) update_ntt(port_info); // State change might require PDU update
}

void LacpManager::enable_collecting_distributing(LacpPortInfo& port_info) {
    bool changed = false;
    if (!port_info.get_actor_state_flag(LacpStateFlag::COLLECTING)) {
        port_info.set_actor_state_flag(LacpStateFlag::COLLECTING, true);
        changed = true;
    }
    if (!port_info.get_actor_state_flag(LacpStateFlag::DISTRIBUTING)) {
        port_info.set_actor_state_flag(LacpStateFlag::DISTRIBUTING, true);
        changed = true;
    }
     port_info.is_active_member_of_lag = true; // Now an active member
    if (changed && logger_) {
        logger_->debug("LACP", "Port " + std::to_string(port_info.port_id_physical) + ": Collecting/Distributing enabled. Actor state: 0x" + std::to_string(port_info.actor_state_val));
    }
    if(changed) update_ntt(port_info); // State change might require PDU update
}

bool LacpManager::check_port_ready(const LacpPortInfo& port_info) {
    // "Port_Ready" condition from IEEE 802.1AX Mux Machine diagram.
    // This usually means the port is enabled and LACP is active.
    // The standard doesn't explicitly define "Port_Ready" as a single term in 43.4.13 text,
    // but transitions use "(port_enabled AND lacp_enabled)".
    return port_info.port_enabled && port_info.lacp_enabled;
}

void LacpManager::update_port_selection_status(uint32_t port_id, LacpPortInfo& port_info) {
    // Simplified Selection Logic:
    // A port is considered "selected" if it's part of a configured LAG,
    // its operational parameters (key) match its partner's, and partner is willing to aggregate.
    // This is a placeholder for the full IEEE 802.1AX Selection Logic (section 43.4.8).

    port_info.selected_for_aggregation = false; // Default to not selected

    auto lag_id_opt = get_lag_for_port(port_id);
    if (!lag_id_opt) {
        if (logger_ && port_info.lacp_enabled) logger_->debug("LACP", "Port " + std::to_string(port_id) + ": Not selected (not in any LAG).");
        return; // Not part of any LAG
    }

    // Partner must be known (not defaulted/expired for these checks to be meaningful)
    if (port_info.get_partner_state_flag(LacpStateFlag::DEFAULTED) || port_info.get_partner_state_flag(LacpStateFlag::EXPIRED)) {
        if (logger_) logger_->debug("LACP", "Port " + std::to_string(port_id) + ": Not selected (partner info is defaulted or expired).");
        return;
    }

    if (!port_info.get_partner_state_flag(LacpStateFlag::AGGREGATION)) {
        if (logger_) logger_->debug("LACP", "Port " + std::to_string(port_id) + ": Not selected (partner AGGREGATION flag is false).");
        return; // Partner is not willing to aggregate this link
    }

    // Check if keys match. Actor key should be derived from admin key, or an operationally assigned one.
    // Partner key is learned from PDU.
    if (port_info.actor_key_val != port_info.partner_key_val) {
        if (logger_) logger_->debug("LACP", "Port " + std::to_string(port_id) + ": Not selected (actor key " +
                                           std::to_string(port_info.actor_key_val) + " != partner key " +
                                           std::to_string(port_info.partner_key_val) + ").");
        return;
    }

    // Basic compatibility checks passed. More complex logic would go into a full Selection Machine.
    // E.g. System ID matching for some configurations, or ensuring consistent aggregator formation.
    // For now, if keys match and partner is willing, consider it selectable.
    port_info.selected_for_aggregation = true;
    if (logger_) logger_->debug("LACP", "Port " + std::to_string(port_id) + ": Selected for aggregation.");
}

bool LacpManager::check_aggregator_ready_for_port(const LacpPortInfo& port_info) {
    // "Ready" as per Mux machine: means partner is IN_SYNC.
    // A port can be attached to an aggregator if its partner is synchronized.
    return port_info.get_partner_state_flag(LacpStateFlag::SYNCHRONIZATION);
}

bool LacpManager::check_partner_in_sync(const LacpPortInfo& port_info) {
    return port_info.get_partner_state_flag(LacpStateFlag::SYNCHRONIZATION);
}

bool LacpManager::check_partner_in_sync_and_collecting(const LacpPortInfo& port_info) {
    return port_info.get_partner_state_flag(LacpStateFlag::SYNCHRONIZATION) &&
           port_info.get_partner_state_flag(LacpStateFlag::COLLECTING);
}
void LacpManager::stop_wait_while_timer(LacpPortInfo& port_info){
    port_info.current_wait_while_timer_ticks = 0;
    port_info.wait_while_timer_expired_event = false; // Clear any pending event
}

// --- LacpManager::run_lacp_mux_machine ---
void LacpManager::run_lacp_mux_machine(uint32_t port_id) {
    auto port_info_it = port_lacp_info_.find(port_id);
    if (port_info_it == port_lacp_info_.end()) {
        if (logger_) logger_->error("LACP", "MuxMachine: Port " + std::to_string(port_id) + " not found.");
        return;
    }
    LacpPortInfo& port_info = port_info_it->second;
    LacpPortInfo::MuxMachineState current_mux_state_for_log = port_info.mux_state;

    // Update selection status at the beginning of each run for this port
    update_port_selection_status(port_id, port_info);
    bool is_port_ready = check_port_ready(port_info); // Composite: port_enabled && lacp_enabled

    switch (port_info.mux_state) {
        case LacpPortInfo::MuxMachineState::DETACHED:
            // Entry actions for DETACHED already effectively done by initialize or previous state's exit
            // but good to ensure them here if coming from an unexpected path.
            port_info.set_actor_state_flag(LacpStateFlag::SYNCHRONIZATION, false);
            detach_mux_from_aggregator(port_id, port_info); // Ensure it's not part of active selection
            disable_collecting_distributing(port_info);

            if (port_info.selected_for_aggregation && is_port_ready) {
                port_info.mux_state = LacpPortInfo::MuxMachineState::WAITING;
                // Action on entry to WAITING:
                port_info.current_wait_while_timer_ticks = AGGREGATE_WAIT_TIME_TICKS;
                port_info.wait_while_timer_expired_event = false; // Clear previous event
                 if (logger_) logger_->debug("LACP", "Port " + std::to_string(port_id) + ": Mux WAITING timer started (" + std::to_string(AGGREGATE_WAIT_TIME_TICKS) + " ticks).");
            }
            break;

        case LacpPortInfo::MuxMachineState::WAITING:
            // Entry action (timer start) is handled on transition into WAITING.
            if (!port_info.selected_for_aggregation || !is_port_ready) {
                port_info.mux_state = LacpPortInfo::MuxMachineState::DETACHED;
                stop_wait_while_timer(port_info);
                // DETACHED entry actions will be applied in the next cycle or immediately.
            } else if (port_info.wait_while_timer_expired_event) {
                port_info.wait_while_timer_expired_event = false; // Consume event
                if (check_aggregator_ready_for_port(port_info)) { // Partner is IN_SYNC
                    port_info.mux_state = LacpPortInfo::MuxMachineState::ATTACHED;
                    // ATTACHED entry actions:
                    port_info.set_actor_state_flag(LacpStateFlag::SYNCHRONIZATION, true);
                    attach_mux_to_aggregator(port_id, port_info);
                    disable_collecting_distributing(port_info); // Still not collecting/distributing
                } else {
                    // Timer expired but partner not ready, stay in WAITING and restart timer?
                    // Standard says: if timer expires, go to ATTACHED (implies Ready was met).
                    // If Ready is false, it should have gone to DETACHED.
                    // This implies check_aggregator_ready_for_port is part of the condition.
                    // Let's assume the AGGREGATE_WAIT_TIMER is to wait for *other* members,
                    // and partner readiness (SYNCHRONIZATION) is a hard gate.
                    // If timer expired but partner still not IN_SYNC, it implies a problem.
                    // The diagram logic for "wait_while_timer expires AND Ready"
                    // "Ready" in the diagram for ATTACHED state in this context means partner is ready to aggregate.
                    if (logger_) logger_->debug("LACP", "Port " + std::to_string(port_id) + ": Mux WAITING timer expired, but partner not ready (SYNC=false). Re-evaluating.");
                    // It might go to DETACHED if selection changes due to this, or simply restart timer.
                    // For now, let's assume it stays in WAITING and timer will be managed by run_timers.
                    // Or, more strictly, if timer expired and condition not met, it should re-evaluate.
                    // The standard is a bit circular here. Let's assume if timer expired and condition not met, it might go to DETACHED.
                    // Re-evaluating `selected_for_aggregation` or `is_port_ready` will handle this.
                    // For simplicity, if timer expired and not ready to attach, stay in WAITING, timer will restart if conditions still hold.
                    // This means the timer must be explicitly restarted here if we are to stay in WAITING.
                    // However, standard implies timer expiry leads to ATTACHED or DETACHED (if conditions change).
                    // Let's assume the timer is only started on *entry* to WAITING. If it expires, a decision is made.
                    // If not ATTACHED, and conditions for WAITING still hold, it will re-enter WAITING and restart timer.
                    // This seems okay.
                }
            }
            break;

        case LacpPortInfo::MuxMachineState::ATTACHED:
            // Entry actions were handled on transition.
            if (!port_info.selected_for_aggregation || !is_port_ready || !check_partner_in_sync(port_info)) {
                port_info.mux_state = LacpPortInfo::MuxMachineState::DETACHED;
                // DETACHED entry actions apply.
            } else if (check_partner_in_sync_and_collecting(port_info)) {
                port_info.mux_state = LacpPortInfo::MuxMachineState::COLLECTING_DISTRIBUTING;
                // C_D entry actions:
                // SYNCHRONIZATION is already true.
                // attach_mux_to_aggregator is already true.
                enable_collecting_distributing(port_info);
            }
            break;

        case LacpPortInfo::MuxMachineState::COLLECTING_DISTRIBUTING:
            // Entry actions were handled on transition.
             if (!port_info.selected_for_aggregation || !is_port_ready || !check_partner_in_sync(port_info) ) {
                port_info.mux_state = LacpPortInfo::MuxMachineState::DETACHED;
                // DETACHED entry actions apply.
            } else if (!check_partner_in_sync_and_collecting(port_info)){
                 port_info.mux_state = LacpPortInfo::MuxMachineState::ATTACHED;
                 // ATTACHED entry actions:
                 disable_collecting_distributing(port_info); // Stop collecting/distributing
                 // SYNCHRONIZATION remains true, attach_mux_to_aggregator remains true.
            }
            break;
    }

    if (logger_ && port_info.mux_state != current_mux_state_for_log) {
         logger_->info("LACP", "Port " + std::to_string(port_id) + ": MuxMachine transitioned from " +
                               std::to_string(static_cast<int>(current_mux_state_for_log)) + " to " + // TODO: Enum to string
                               std::to_string(static_cast<int>(port_info.mux_state)));
    }
}

} // namespace netflow
