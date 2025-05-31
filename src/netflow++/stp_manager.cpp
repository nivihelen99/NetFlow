#include "netflow++/stp_manager.hpp"
#include "netflow++/packet.hpp"      // For Packet, EthernetHeader, LLCHeader, MacAddress
#include "netflow++/buffer_pool.hpp" // Required for generate_bpdus access to BufferPool
#include "netflow++/logger.hpp"      // For SwitchLogger
#include <iostream> // For temporary logging during development (replace with logger)
#include <vector>
#include <algorithm> // For std::min, std::find_if etc.
#include <cstring>   // For memcpy
#include <sstream>   // Required for std::ostringstream
#include <iomanip>   // Required for std::hex and std::setfill/setw
#include <string>    // Required for std::string
#include <cstdint>   // Required for uint64_t

// Ensure network byte order utilities are available.
#if !defined(htonll) && !defined(ntohll)
    #if __has_include(<arpa/inet.h>)
    #elif __has_include(<winsock2.h>)
    #else
    #endif
#endif

namespace { // Anonymous namespace for file-local helper
std::string stp_uint64_to_hex_string(uint64_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setfill('0') << std::setw(16) << value;
    return oss.str();
}
} // end anonymous namespace


namespace netflow {

// --- ConfigBpdu Method Definitions ---
ConfigBpdu::ConfigBpdu() :
    protocol_id(StpDefaults::PROTOCOL_ID), version_id(StpDefaults::VERSION_ID_STP),
    bpdu_type(StpDefaults::BPDU_TYPE_CONFIG), flags(0),
    root_id(0), root_path_cost(0), bridge_id(0), port_id(0),
    message_age(0), max_age(0), hello_time(0), forward_delay(0) {
}

uint64_t ConfigBpdu::htonll(uint64_t val) {
    if (__BYTE_ORDER == __LITTLE_ENDIAN) {
        return (((uint64_t)htonl(static_cast<uint32_t>(val & 0xFFFFFFFF))) << 32) | htonl(static_cast<uint32_t>(val >> 32));
    }
    return val;
}

uint64_t ConfigBpdu::ntohll(uint64_t val) {
    if (__BYTE_ORDER == __LITTLE_ENDIAN) {
        return (((uint64_t)ntohl(static_cast<uint32_t>(val & 0xFFFFFFFF))) << 32) | ntohl(static_cast<uint32_t>(val >> 32));
    }
    return val;
}

void ConfigBpdu::from_bpdu_info_for_sending(const ReceivedBpduInfo& source_info,
                                            uint64_t my_bridge_id_val, uint16_t my_port_id_val,
                                            uint16_t effective_message_age_val, uint16_t root_max_age_val,
                                            uint16_t root_hello_time_val, uint16_t root_forward_delay_val) {
    protocol_id = StpDefaults::PROTOCOL_ID;
    version_id = StpDefaults::VERSION_ID_STP;
    bpdu_type = StpDefaults::BPDU_TYPE_CONFIG;
    root_id = htonll(source_info.root_id);
    root_path_cost = htonl(source_info.root_path_cost);
    bridge_id = htonll(my_bridge_id_val);
    port_id = htons(my_port_id_val);
    message_age = htons(effective_message_age_val);
    max_age = htons(root_max_age_val);
    hello_time = htons(root_hello_time_val);
    forward_delay = htons(root_forward_delay_val);
    flags = (source_info.tc_flag ? 0x01 : 0x00) | (source_info.tca_flag ? 0x80 : 0x00);
}

ReceivedBpduInfo ConfigBpdu::to_received_bpdu_info() const {
    ReceivedBpduInfo info;
    info.root_id = ntohll(root_id);
    info.root_path_cost = ntohl(root_path_cost);
    info.sender_bridge_id = ntohll(bridge_id);
    info.sender_port_id = ntohs(port_id);
    info.message_age = ntohs(message_age);
    info.max_age = ntohs(max_age);
    info.hello_time = ntohs(hello_time);
    info.forward_delay = ntohs(forward_delay);
    info.tc_flag = (flags & 0x01);
    info.tca_flag = (flags & 0x80);
    return info;
}

// --- ReceivedBpduInfo Method Definitions ---
bool ReceivedBpduInfo::is_superior_to(const ReceivedBpduInfo& other, uint64_t self_bridge_id) const {
    if (this->root_id < other.root_id) return true;
    if (this->root_id > other.root_id) return false;
    if (this->root_path_cost < other.root_path_cost) return true;
    if (this->root_path_cost > other.root_path_cost) return false;
    if (this->sender_bridge_id < other.sender_bridge_id) return true;
    if (this->sender_bridge_id > other.sender_bridge_id) return false;
    if (this->sender_port_id < other.sender_port_id) return true;
    if (this->sender_port_id > other.sender_port_id) return false;
    return false;
}

// --- StpPortInfo Method Definitions ---
StpManager::StpPortInfo::StpPortInfo(uint32_t id)
    : port_id_internal(id),
      role(PortRole::DISABLED),
      state(PortState::DISABLED),
      path_cost_to_segment(19),
      designated_bridge_id_for_segment(0),
      designated_port_id_for_segment(0),
      path_cost_from_designated_bridge_to_root(0xFFFFFFFF),
      message_age_timer_seconds(0),
      forward_delay_timer_seconds(0),
      hello_timer_seconds(0),
      new_bpdu_received_flag(false),
      port_priority(128) {
    update_stp_port_id_field();
}

void StpManager::StpPortInfo::update_stp_port_id_field() {
    stp_port_id_field = static_cast<uint16_t>(((port_priority >> 4) & 0x0F) << 12) | (port_id_internal & 0x0FFF);
}

bool StpManager::StpPortInfo::has_valid_bpdu_info(uint16_t max_age_limit_seconds) const {
    return received_bpdu.sender_bridge_id != 0xFFFFFFFFFFFFFFFFULL &&
           message_age_timer_seconds < (received_bpdu.max_age / 256);
}

uint32_t StpManager::StpPortInfo::get_total_path_cost_to_root_via_port() const {
    if (path_cost_from_designated_bridge_to_root == 0xFFFFFFFF) {
        return 0xFFFFFFFF;
    }
    return path_cost_from_designated_bridge_to_root + path_cost_to_segment;
}

// --- BridgeConfig Method Definitions ---
StpManager::BridgeConfig::BridgeConfig(uint64_t mac, uint16_t priority,
                                       uint32_t hello, uint32_t fwd_delay, uint32_t age)
    : bridge_mac_address(mac), bridge_priority(priority),
      hello_time_seconds(hello), forward_delay_seconds(fwd_delay), max_age_seconds(age) {
    update_bridge_id_value();
    our_bpdu_info.root_id = bridge_id_value;
    our_bpdu_info.root_path_cost = 0;
    our_bpdu_info.sender_bridge_id = bridge_id_value;
    our_bpdu_info.sender_port_id = 0;
    our_bpdu_info.message_age = 0;
    our_bpdu_info.max_age = max_age_seconds * 256;
    our_bpdu_info.hello_time = hello_time_seconds * 256;
    our_bpdu_info.forward_delay = forward_delay_seconds * 256;
    our_bpdu_info.tc_flag = false;
    our_bpdu_info.tca_flag = false;
    root_port_internal_id.reset();
}

void StpManager::BridgeConfig::update_bridge_id_value() {
    bridge_id_value = (static_cast<uint64_t>(bridge_priority) << 48) | (bridge_mac_address & 0x0000FFFFFFFFFFFFULL);
}

bool StpManager::BridgeConfig::is_root_bridge() const {
    return our_bpdu_info.root_id == bridge_id_value;
}

// --- StpManager Constructor ---
StpManager::StpManager(uint32_t num_ports, uint64_t switch_mac_address, uint16_t switch_priority)
    : bridge_config_(switch_mac_address, switch_priority) {
    initialize_ports(num_ports);
}

// --- StpManager::initialize_ports ---
void StpManager::initialize_ports(uint32_t num_ports) {
    port_stp_info_.clear();
    for (uint32_t i = 0; i < num_ports; ++i) {
        port_stp_info_[i] = StpPortInfo(i);
        StpPortInfo& p_info = port_stp_info_[i];
        p_info.state = PortState::BLOCKING;
        p_info.role = PortRole::DISABLED;
        p_info.designated_bridge_id_for_segment = bridge_config_.bridge_id_value;
        p_info.designated_port_id_for_segment = p_info.stp_port_id_field;
        p_info.path_cost_from_designated_bridge_to_root = 0;
        p_info.received_bpdu.root_id = bridge_config_.bridge_id_value;
        p_info.received_bpdu.root_path_cost = 0;
        p_info.received_bpdu.sender_bridge_id = bridge_config_.bridge_id_value;
        p_info.received_bpdu.sender_port_id = p_info.stp_port_id_field;
        p_info.received_bpdu.message_age = 0;
        p_info.received_bpdu.max_age = bridge_config_.our_bpdu_info.max_age;
        p_info.received_bpdu.hello_time = bridge_config_.our_bpdu_info.hello_time;
        p_info.received_bpdu.forward_delay = bridge_config_.our_bpdu_info.forward_delay;
    }
}

// --- StpManager::process_bpdu ---
void StpManager::process_bpdu(const Packet& bpdu_packet, uint32_t ingress_port_id, SwitchLogger& logger) {
    auto port_it = port_stp_info_.find(ingress_port_id);
    if (port_it == port_stp_info_.end()) {
        logger.warning("STP_BPDU", "BPDU received on unknown port: " + std::to_string(ingress_port_id));
        return;
    }
    StpPortInfo& p_info = port_it->second;
    if (p_info.state == PortState::DISABLED) {
        logger.debug("STP_BPDU", "BPDU on disabled port " + std::to_string(ingress_port_id) + ", ignoring.");
        return;
    }
    const PacketBuffer* pb = bpdu_packet.get_buffer();
    if (!pb || pb->size < (sizeof(EthernetHeader) + sizeof(LLCHeader) + CONFIG_BPDU_PAYLOAD_SIZE)) {
        logger.warning("STP_BPDU", "Packet too small for BPDU on port " + std::to_string(ingress_port_id));
        return;
    }
    const uint8_t* bpdu_payload_start = pb->data + sizeof(EthernetHeader) + sizeof(LLCHeader);
    size_t bpdu_payload_length = pb->size - (sizeof(EthernetHeader) + sizeof(LLCHeader));
    if (bpdu_payload_length < CONFIG_BPDU_PAYLOAD_SIZE) {
        logger.warning("STP_BPDU", "BPDU payload too short on port " + std::to_string(ingress_port_id));
        return;
    }
    ConfigBpdu received_config_bpdu_raw;
    memcpy(&received_config_bpdu_raw, bpdu_payload_start, CONFIG_BPDU_PAYLOAD_SIZE);
    if (received_config_bpdu_raw.protocol_id != StpDefaults::PROTOCOL_ID ||
        received_config_bpdu_raw.version_id != StpDefaults::VERSION_ID_STP ||
        received_config_bpdu_raw.bpdu_type != StpDefaults::BPDU_TYPE_CONFIG) {
        logger.debug("STP_BPDU", "Non-Config/Invalid BPDU on port " + std::to_string(ingress_port_id));
        return;
    }
    ReceivedBpduInfo new_bpdu_info = received_config_bpdu_raw.to_received_bpdu_info();
    logger.info("STP_BPDU", "Config BPDU received on port " + std::to_string(ingress_port_id) +
                              ": RootID=" + stp_uint64_to_hex_string(new_bpdu_info.root_id) +
                              ", SenderBID=" + stp_uint64_to_hex_string(new_bpdu_info.sender_bridge_id) +
                              ", Cost=" + std::to_string(new_bpdu_info.root_path_cost));
    p_info.received_bpdu = new_bpdu_info;
    p_info.message_age_timer_seconds = 0;
    p_info.new_bpdu_received_flag = true;
    recalculate_stp_roles_and_states(logger);
}

// --- StpManager::generate_bpdus ---
std::vector<Packet> StpManager::generate_bpdus(BufferPool& buffer_pool, SwitchLogger& logger) {
    std::vector<Packet> bpdus_to_send;
    for (auto& pair_port_info : port_stp_info_) {
        uint32_t port_id = pair_port_info.first;
        StpPortInfo& p_info = pair_port_info.second;
        if (p_info.role == PortRole::DESIGNATED &&
            p_info.state != PortState::DISABLED &&
            p_info.state != PortState::BLOCKING) {
            if (p_info.hello_timer_seconds >= bridge_config_.hello_time_seconds) {
                p_info.hello_timer_seconds = 0;
                ConfigBpdu bpdu_to_send_struct;
                ReceivedBpduInfo params_for_bpdu = bridge_config_.our_bpdu_info;
                uint16_t msg_age_for_bpdu = params_for_bpdu.message_age;
                if (!bridge_config_.is_root_bridge()) {
                     msg_age_for_bpdu += (1 * 256);
                }
                if (msg_age_for_bpdu >= params_for_bpdu.max_age) {
                    logger.warning("STP_BPDU_GEN", "Msg age would exceed Max age for BPDU on port " + std::to_string(port_id));
                    continue;
                }
                bpdu_to_send_struct.from_bpdu_info_for_sending(
                    params_for_bpdu, bridge_config_.bridge_id_value, p_info.stp_port_id_field,
                    msg_age_for_bpdu, params_for_bpdu.max_age, params_for_bpdu.hello_time, params_for_bpdu.forward_delay);
                bpdu_to_send_struct.flags = (params_for_bpdu.tc_flag ? 0x01 : 0x00) | (params_for_bpdu.tca_flag ? 0x80 : 0x00);
                size_t total_bpdu_size = sizeof(EthernetHeader) + sizeof(LLCHeader) + CONFIG_BPDU_PAYLOAD_SIZE;
                PacketBuffer* pb = buffer_pool.allocate_buffer(total_bpdu_size);
                if (!pb) {
                    logger.error("STP_BPDU_GEN", "Buffer allocation failed for BPDU on port " + std::to_string(port_id));
                    continue;
                }
                pb->size = total_bpdu_size;
                memset(pb->data, 0, total_bpdu_size);
                EthernetHeader* eth_hdr = reinterpret_cast<EthernetHeader*>(pb->data);
                uint8_t stp_dst_mac_bytes[] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x00};
                eth_hdr->dst_mac = MacAddress(stp_dst_mac_bytes);
                uint8_t bridge_mac_bytes[6];
                uint64_t temp_mac = bridge_config_.bridge_mac_address;
                for(int i=0; i<6; ++i) bridge_mac_bytes[5-i] = (temp_mac >> (i*8)) & 0xFF;
                eth_hdr->src_mac = MacAddress(bridge_mac_bytes);
                eth_hdr->ethertype = htons(sizeof(LLCHeader) + CONFIG_BPDU_PAYLOAD_SIZE);
                LLCHeader* llc_hdr = reinterpret_cast<LLCHeader*>(pb->data + sizeof(EthernetHeader));
                llc_hdr->dsap = 0x42;
                llc_hdr->ssap = 0x42;
                llc_hdr->control = 0x03;
                memcpy(pb->data + sizeof(EthernetHeader) + sizeof(LLCHeader), &bpdu_to_send_struct, CONFIG_BPDU_PAYLOAD_SIZE);
                Packet new_bpdu_packet(pb);
                bpdus_to_send.push_back(new_bpdu_packet);
                logger.info("STP_BPDU_GEN", "Generated BPDU on port " + std::to_string(port_id));
            }
        }
    }
    return bpdus_to_send;
}

// --- StpManager::recalculate_stp_roles_and_states ---
void StpManager::recalculate_stp_roles_and_states(SwitchLogger& logger) {
    ReceivedBpduInfo best_bpdu_for_root_election = bridge_config_.our_bpdu_info;
    best_bpdu_for_root_election.root_id = bridge_config_.bridge_id_value;
    best_bpdu_for_root_election.root_path_cost = 0;
    best_bpdu_for_root_election.sender_bridge_id = bridge_config_.bridge_id_value;
    best_bpdu_for_root_election.sender_port_id = 0;
    best_bpdu_for_root_election.message_age = 0;
    best_bpdu_for_root_election.max_age = bridge_config_.max_age_seconds * 256;
    best_bpdu_for_root_election.hello_time = bridge_config_.hello_time_seconds * 256;
    best_bpdu_for_root_election.forward_delay = bridge_config_.forward_delay_seconds * 256;
    std::optional<uint32_t> new_root_port_id;
    for (auto& pair_port_info : port_stp_info_) {
        StpPortInfo& p_info = pair_port_info.second;
        if (p_info.state == PortState::DISABLED) continue;
        if (p_info.has_valid_bpdu_info(bridge_config_.max_age_seconds)) {
            if (p_info.received_bpdu.is_superior_to(best_bpdu_for_root_election, bridge_config_.bridge_id_value)) {
                best_bpdu_for_root_election = p_info.received_bpdu;
            }
        }
    }
    bridge_config_.our_bpdu_info.root_id = best_bpdu_for_root_election.root_id;
    bridge_config_.our_bpdu_info.max_age = best_bpdu_for_root_election.max_age;
    bridge_config_.our_bpdu_info.hello_time = best_bpdu_for_root_election.hello_time;
    bridge_config_.our_bpdu_info.forward_delay = best_bpdu_for_root_election.forward_delay;
    if (bridge_config_.is_root_bridge()) {
        bridge_config_.our_bpdu_info.root_path_cost = 0;
        bridge_config_.our_bpdu_info.sender_bridge_id = bridge_config_.bridge_id_value;
        bridge_config_.our_bpdu_info.sender_port_id = 0;
        bridge_config_.our_bpdu_info.message_age = 0;
        bridge_config_.root_port_internal_id.reset();
        logger.info("STP_RECALC", "This bridge (" + stp_uint64_to_hex_string(bridge_config_.bridge_id_value) + ") is ROOT.");
    } else {
        uint32_t calculated_rpc_for_bridge = 0xFFFFFFFF;
        for (auto& pair_port_info : port_stp_info_) {
             StpPortInfo& p_info = pair_port_info.second;
             if (p_info.state == PortState::DISABLED) continue;
            if (p_info.has_valid_bpdu_info(bridge_config_.max_age_seconds) &&
                p_info.received_bpdu.root_id == bridge_config_.our_bpdu_info.root_id) {
                uint32_t cost_via_this_port = p_info.received_bpdu.root_path_cost + p_info.path_cost_to_segment;
                if (!new_root_port_id.has_value() || cost_via_this_port < calculated_rpc_for_bridge) {
                    calculated_rpc_for_bridge = cost_via_this_port;
                    new_root_port_id = p_info.port_id_internal;
                } else if (cost_via_this_port == calculated_rpc_for_bridge) {
                    StpPortInfo& current_best_rp_info = port_stp_info_.at(new_root_port_id.value());
                    if (p_info.received_bpdu.sender_bridge_id < current_best_rp_info.received_bpdu.sender_bridge_id) {
                         new_root_port_id = p_info.port_id_internal;
                    } else if (p_info.received_bpdu.sender_bridge_id == current_best_rp_info.received_bpdu.sender_bridge_id &&
                               p_info.received_bpdu.sender_port_id < current_best_rp_info.received_bpdu.sender_port_id) {
                         new_root_port_id = p_info.port_id_internal;
                    }
                }
            }
        }
        bridge_config_.root_port_internal_id = new_root_port_id;
        if (new_root_port_id.has_value()) {
            bridge_config_.our_bpdu_info.root_path_cost = calculated_rpc_for_bridge;
            bridge_config_.our_bpdu_info.sender_bridge_id = bridge_config_.bridge_id_value;
            bridge_config_.our_bpdu_info.sender_port_id = port_stp_info_.at(new_root_port_id.value()).stp_port_id_field;
            bridge_config_.our_bpdu_info.message_age = port_stp_info_.at(new_root_port_id.value()).received_bpdu.message_age;
            logger.info("STP_RECALC", "This bridge is NOT ROOT. Root Port: " + std::to_string(new_root_port_id.value()) +
                                     ", New Root Path Cost: " + std::to_string(calculated_rpc_for_bridge));
        } else {
            logger.warning("STP_RECALC", "No path to known root " + stp_uint64_to_hex_string(bridge_config_.our_bpdu_info.root_id) + ". Reverting to self as root.");
            bridge_config_.our_bpdu_info.root_id = bridge_config_.bridge_id_value;
            bridge_config_.our_bpdu_info.root_path_cost = 0;
            bridge_config_.our_bpdu_info.sender_bridge_id = bridge_config_.bridge_id_value;
            bridge_config_.our_bpdu_info.sender_port_id = 0;
            bridge_config_.our_bpdu_info.message_age = 0;
            bridge_config_.our_bpdu_info.max_age = bridge_config_.max_age_seconds * 256;
            bridge_config_.our_bpdu_info.hello_time = bridge_config_.hello_time_seconds * 256;
            bridge_config_.our_bpdu_info.forward_delay = bridge_config_.forward_delay_seconds * 256;
        }
    }
    for (auto& pair_port_info : port_stp_info_) {
        StpPortInfo& p_info = pair_port_info.second;
        if (p_info.state == PortState::DISABLED) {
            p_info.role = PortRole::DISABLED;
            continue;
        }
        if (bridge_config_.is_root_bridge()) {
            p_info.role = PortRole::DESIGNATED;
            p_info.designated_bridge_id_for_segment = bridge_config_.bridge_id_value;
            p_info.designated_port_id_for_segment = p_info.stp_port_id_field;
            p_info.path_cost_from_designated_bridge_to_root = 0;
        } else {
            if (bridge_config_.root_port_internal_id.has_value() && p_info.port_id_internal == bridge_config_.root_port_internal_id.value()) {
                p_info.role = PortRole::ROOT;
                p_info.designated_bridge_id_for_segment = p_info.received_bpdu.sender_bridge_id;
                p_info.designated_port_id_for_segment = p_info.received_bpdu.sender_port_id;
                p_info.path_cost_from_designated_bridge_to_root = p_info.received_bpdu.root_path_cost;
            } else {
                ReceivedBpduInfo our_offer_bpdu = bridge_config_.our_bpdu_info;
                our_offer_bpdu.sender_port_id = p_info.stp_port_id_field;
                if (p_info.has_valid_bpdu_info(bridge_config_.max_age_seconds) &&
                    p_info.received_bpdu.is_superior_to(our_offer_bpdu, bridge_config_.bridge_id_value)) {
                    p_info.role = PortRole::ALTERNATE;
                    p_info.designated_bridge_id_for_segment = p_info.received_bpdu.sender_bridge_id;
                    p_info.designated_port_id_for_segment = p_info.received_bpdu.sender_port_id;
                    p_info.path_cost_from_designated_bridge_to_root = p_info.received_bpdu.root_path_cost;
                } else {
                    p_info.role = PortRole::DESIGNATED;
                    p_info.designated_bridge_id_for_segment = bridge_config_.bridge_id_value;
                    p_info.designated_port_id_for_segment = p_info.stp_port_id_field;
                    p_info.path_cost_from_designated_bridge_to_root = bridge_config_.our_bpdu_info.root_path_cost;
                }
            }
        }
        PortState old_state = p_info.state;
        switch (p_info.role) {
            case PortRole::ROOT:
            case PortRole::DESIGNATED:
                if (p_info.state == PortState::BLOCKING || p_info.state == PortState::UNKNOWN) {
                    p_info.state = PortState::LISTENING;
                    p_info.forward_delay_timer_seconds = 0;
                }
                break;
            case PortRole::ALTERNATE:
            case PortRole::BACKUP:
            case PortRole::DISABLED:
                p_info.state = PortState::BLOCKING;
                p_info.forward_delay_timer_seconds = 0;
                break;
            case PortRole::UNKNOWN:
                p_info.state = PortState::BLOCKING;
                break;
        }
        if (old_state != p_info.state) {
             logger.info("STP_STATE_CHANGE", "Port " + std::to_string(p_info.port_id_internal) +
                                          " changed from " + port_state_to_string(old_state) +
                                          " to " + port_state_to_string(p_info.state) +
                                          " (Role: " + port_role_to_string(p_info.role) + ")");
        }
         p_info.new_bpdu_received_flag = false;
    }
}

// --- Helper methods for converting enum to string ---
std::string StpManager::port_state_to_string(PortState state) const {
    switch (state) {
        case PortState::UNKNOWN:   return "UNKNOWN";
        case PortState::DISABLED:  return "DISABLED";
        case PortState::BLOCKING:  return "BLOCKING";
        case PortState::LISTENING: return "LISTENING";
        case PortState::LEARNING:  return "LEARNING";
        case PortState::FORWARDING:return "FORWARDING";
        default:                   return "INVALID_STATE";
    }
}

std::string StpManager::port_role_to_string(PortRole role) const {
    switch (role) {
        case PortRole::UNKNOWN:    return "UNKNOWN";
        case PortRole::ROOT:       return "ROOT";
        case PortRole::DESIGNATED: return "DESIGNATED";
        case PortRole::ALTERNATE:  return "ALTERNATE";
        case PortRole::BACKUP:     return "BACKUP";
        case PortRole::DISABLED:   return "DISABLED";
        default:                   return "INVALID_ROLE";
    }
}

} // namespace netflow
