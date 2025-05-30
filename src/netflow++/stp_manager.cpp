#include "netflow++/stp_manager.hpp"
#include "netflow++/packet.hpp"      // For Packet, EthernetHeader, LLCHeader, MacAddress
#include "netflow++/buffer_pool.hpp" // Required for generate_bpdus access to BufferPool
#include "netflow++/logger.hpp"      // For SwitchLogger
#include <iostream> // For temporary logging during development (replace with logger)
#include <vector>
#include <algorithm> // For std::min, std::find_if etc.
#include <cstring>   // For memcpy

// Ensure network byte order utilities are available.
// These might be system-dependent or part of a utility header.
// For simplicity, providing basic versions if not found, similar to packet.hpp.
#if !defined(htonll) && !defined(ntohll) // Check if already defined (e.g. by ConfigBpdu in header)
    #if __has_include(<arpa/inet.h>)
        // System provides them (usually only for 16/32 bit)
        // 64-bit might need custom implementation if not available via system headers implicitly
    #elif __has_include(<winsock2.h>)
        // Windows
    #else
        // Basic fallbacks if no system headers known for these specifically for 64-bit
        // These are often defined as static methods in ConfigBpdu now.
    #endif

// Define static helpers if they are not part of ConfigBpdu in the header
// These were defined in ConfigBpdu struct in the header as per latest stp_manager.hpp modification.
// If they are needed here independently, they could be defined in an anonymous namespace or as static.
// For now, assume they are accessible via ConfigBpdu::htonll / ConfigBpdu::ntohll from the header.
#endif


namespace netflow {

// --- ConfigBpdu Method Definitions ---
ConfigBpdu::ConfigBpdu() :
    protocol_id(StpDefaults::PROTOCOL_ID), version_id(StpDefaults::VERSION_ID_STP),
    bpdu_type(StpDefaults::BPDU_TYPE_CONFIG), flags(0),
    root_id(0), root_path_cost(0), bridge_id(0), port_id(0),
    message_age(0), max_age(0), hello_time(0), forward_delay(0) {
    // All members initialized via member initializer list or are fundamental types zero-initialized.
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
    // Basic validation already done by caller in StpManager::process_bpdu for type, version, proto
    // if (protocol_id != StpDefaults::PROTOCOL_ID || version_id != StpDefaults::VERSION_ID_STP || bpdu_type != StpDefaults::BPDU_TYPE_CONFIG) {
    //     info.root_id = 0xFFFFFFFFFFFFFFFFULL;
    //     return info;
    // }
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
    // Lower Root ID is better
    if (this->root_id < other.root_id) return true;
    if (this->root_id > other.root_id) return false;

    // Same Root ID, lower Root Path Cost is better
    if (this->root_path_cost < other.root_path_cost) return true;
    if (this->root_path_cost > other.root_path_cost) return false;

    // Same Root ID and RPC, lower Sender Bridge ID is better
    if (this->sender_bridge_id < other.sender_bridge_id) return true;
    if (this->sender_bridge_id > other.sender_bridge_id) return false;

    // Same Root ID, RPC, Sender BID, lower Sender Port ID is better
    if (this->sender_port_id < other.sender_port_id) return true;
    if (this->sender_port_id > other.sender_port_id) return false;

    // IEEE 802.1D-2004 specifies one more tie-breaker: the BPDU received on the port with the lower Port Identifier
    // This is handled by the port selection logic itself when comparing BPDUs from different ports.
    // If 'this' BPDU and 'other' BPDU are for the same port or being compared globally, this final tie-breaker isn't applicable here directly.

    return false; // Otherwise, not strictly superior (could be equal or inferior)
}


// --- StpPortInfo Method Definitions ---
StpManager::StpPortInfo::StpPortInfo(uint32_t id)
    : port_id_internal(id),
      role(PortRole::DISABLED), // Initial role as per latest header
      state(PortState::DISABLED), // Initial state as per latest header
      path_cost_to_segment(19), // Default, should be configurable by speed
      designated_bridge_id_for_segment(0),
      designated_port_id_for_segment(0),
      path_cost_from_designated_bridge_to_root(0xFFFFFFFF),
      message_age_timer_seconds(0),
      forward_delay_timer_seconds(0),
      hello_timer_seconds(0),
      new_bpdu_received_flag(false),
      port_priority(128) {
    update_stp_port_id_field();
    // received_bpdu uses default constructor (worst values)
}

void StpManager::StpPortInfo::update_stp_port_id_field() {
    // STP Port ID: 4 bits priority (MSB of port_priority) + 12 bits port index (port_id_internal)
    // Standard combines 4-bit priority (0-240, steps of 16) and 12-bit port number.
    // Here, port_priority is 8-bit. We take its upper 4 bits.
    stp_port_id_field = static_cast<uint16_t>(((port_priority >> 4) & 0x0F) << 12) | (port_id_internal & 0x0FFF);
}

bool StpManager::StpPortInfo::has_valid_bpdu_info(uint16_t max_age_limit_seconds) const {
    // Compares this port's BPDU info age against the max_age limit from the *received BPDU's* max_age value.
    // The message_age_timer_seconds counts how long *we* have held this BPDU info without refresh.
    // The received_bpdu.message_age is the age accumulated up to the sender.
    // Total age = received_bpdu.message_age/256 + message_age_timer_seconds.
    // This should be compared against received_bpdu.max_age/256.
    // The run_stp_timers logic handles aging out based on message_age_timer_seconds vs received_bpdu.max_age/256.
    // So this function can just check if the sender is valid.
    return received_bpdu.sender_bridge_id != 0xFFFFFFFFFFFFFFFFULL &&
           message_age_timer_seconds < (received_bpdu.max_age / 256); // Ensure it hasn't locally timed out
}

uint32_t StpManager::StpPortInfo::get_total_path_cost_to_root_via_port() const {
    // This would be the cost recorded in a BPDU received on this port + this port's own path_cost_to_segment
    // However, the StpPortInfo stores path_cost_from_designated_bridge_to_root, which is from the BPDU.
    // So, it should be path_cost_from_designated_bridge_to_root + path_cost_to_segment.
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
    // Initially, assume self is root for 'our_bpdu_info'
    our_bpdu_info.root_id = bridge_id_value;
    our_bpdu_info.root_path_cost = 0;
    our_bpdu_info.sender_bridge_id = bridge_id_value;
    our_bpdu_info.sender_port_id = 0; // Port 0 indicates from bridge itself
    our_bpdu_info.message_age = 0;
    our_bpdu_info.max_age = max_age_seconds * 256;
    our_bpdu_info.hello_time = hello_time_seconds * 256;
    our_bpdu_info.forward_delay = forward_delay_seconds * 256;
    our_bpdu_info.tc_flag = false;
    our_bpdu_info.tca_flag = false;
    root_port_internal_id.reset();
}

void StpManager::BridgeConfig::update_bridge_id_value() {
    // Bridge ID: 16 bits priority + 48 bits MAC address
    bridge_id_value = (static_cast<uint64_t>(bridge_priority) << 48) | (bridge_mac_address & 0x0000FFFFFFFFFFFFULL);
}

bool StpManager::BridgeConfig::is_root_bridge() const {
    return our_bpdu_info.root_id == bridge_id_value;
}


// --- StpManager Constructor ---
StpManager::StpManager(uint32_t num_ports, uint64_t switch_mac_address, uint16_t switch_priority)
    : bridge_config_(switch_mac_address, switch_priority) { // BridgeConfig constructor handles MAC and priority
    // Logger might be passed here if needed for init logging.
    // For now, assume logger is passed to methods that need it.
    initialize_ports(num_ports);
    // Initial calculation of roles and states.
    // SwitchLogger dummy_logger; // Placeholder if no logger passed to constructor
    // recalculate_stp_roles_and_states(dummy_logger);
    // Postponing initial recalculation to be called explicitly by Switch class after full setup.
}

// --- StpManager::initialize_ports ---
void StpManager::initialize_ports(uint32_t num_ports) {
    port_stp_info_.clear();
    for (uint32_t i = 0; i < num_ports; ++i) {
        port_stp_info_[i] = StpPortInfo(i); // StpPortInfo constructor sets defaults

        // Specific initializations based on bridge_config_
        StpPortInfo& p_info = port_stp_info_[i];
        p_info.state = PortState::BLOCKING; // Start all ports in BLOCKING
        p_info.role = PortRole::DISABLED;   // Or UNKNOWN, to be determined by first recalculate
                                            // Setting to DISABLED until explicitly enabled by admin or STP logic.
                                            // However, the subtask implies starting as designated for self.
                                            // Let's align with the previous implementation's spirit for initialization.

        // Each port initially considers itself as the designated port on its segment,
        // with the current bridge as the designated bridge and root.
        p_info.designated_bridge_id_for_segment = bridge_config_.bridge_id_value;
        p_info.designated_port_id_for_segment = p_info.stp_port_id_field; // Its own STP port ID
        p_info.path_cost_from_designated_bridge_to_root = 0; // Cost to root is 0 as we are the root for this segment initially

        // Initialize received_bpdu to reflect no valid BPDU received yet, or self as root.
        // This aligns with the idea that a port starts by advertising itself as root for its segment.
        p_info.received_bpdu.root_id = bridge_config_.bridge_id_value;
        p_info.received_bpdu.root_path_cost = 0;
        p_info.received_bpdu.sender_bridge_id = bridge_config_.bridge_id_value;
        p_info.received_bpdu.sender_port_id = p_info.stp_port_id_field;
        p_info.received_bpdu.message_age = 0;
        p_info.received_bpdu.max_age = bridge_config_.our_bpdu_info.max_age; // Use our configured timers
        p_info.received_bpdu.hello_time = bridge_config_.our_bpdu_info.hello_time;
        p_info.received_bpdu.forward_delay = bridge_config_.our_bpdu_info.forward_delay;

        // Default path_cost_to_segment (e.g. for 100Mbps). Should be updated based on actual port speed.
        // This was in StpPortInfo constructor in prior versions of header.
        // p_info.path_cost_to_segment = 19;
    }
}

// --- StpManager::process_bpdu ---
void StpManager::process_bpdu(const Packet& bpdu_packet, uint32_t ingress_port_id, SwitchLogger& logger) {
    auto port_it = port_stp_info_.find(ingress_port_id);
    if (port_it == port_stp_info_.end()) {
        logger.warn("STP_BPDU", "BPDU received on unknown port: " + std::to_string(ingress_port_id));
        return;
    }

    StpPortInfo& p_info = port_it->second;
    if (p_info.state == PortState::DISABLED) {
        logger.debug("STP_BPDU", "BPDU on disabled port " + std::to_string(ingress_port_id) + ", ignoring.");
        return;
    }

    const PacketBuffer* pb = bpdu_packet.get_buffer();
    // Check for minimum LACPDU size here, assuming Ethernet header is already parsed by Switch.
    // The packet passed to process_bpdu might be just the L2 payload.
    // For now, assume it's a full Ethernet frame.
    if (!pb || pb->size < (sizeof(EthernetHeader) + sizeof(LLCHeader) + CONFIG_BPDU_PAYLOAD_SIZE)) {
        logger.warn("STP_BPDU", "Packet too small for BPDU on port " + std::to_string(ingress_port_id));
        return;
    }

    const uint8_t* bpdu_payload_start = pb->data + sizeof(EthernetHeader) + sizeof(LLCHeader);
    size_t bpdu_payload_length = pb->size - (sizeof(EthernetHeader) + sizeof(LLCHeader));

    if (bpdu_payload_length < CONFIG_BPDU_PAYLOAD_SIZE) {
        logger.warn("STP_BPDU", "BPDU payload too short on port " + std::to_string(ingress_port_id));
        return;
    }

    ConfigBpdu received_config_bpdu_raw; // Temporary raw storage
    memcpy(&received_config_bpdu_raw, bpdu_payload_start, CONFIG_BPDU_PAYLOAD_SIZE);

    if (received_config_bpdu_raw.protocol_id != StpDefaults::PROTOCOL_ID ||
        received_config_bpdu_raw.version_id != StpDefaults::VERSION_ID_STP ||
        received_config_bpdu_raw.bpdu_type != StpDefaults::BPDU_TYPE_CONFIG) {
        logger.debug("STP_BPDU", "Non-Config/Invalid BPDU on port " + std::to_string(ingress_port_id));
        return;
    }

    ReceivedBpduInfo new_bpdu_info = received_config_bpdu_raw.to_received_bpdu_info();
    logger.info("STP_BPDU", "Config BPDU received on port " + std::to_string(ingress_port_id) +
                              ": RootID=" + logger.uint64_to_hex_string(new_bpdu_info.root_id) +
                              ", SenderBID=" + logger.uint64_to_hex_string(new_bpdu_info.sender_bridge_id) +
                              ", Cost=" + std::to_string(new_bpdu_info.root_path_cost));

    p_info.received_bpdu = new_bpdu_info;
    p_info.message_age_timer_seconds = 0; // Reset timer because we got a new BPDU
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
                ReceivedBpduInfo params_for_bpdu = bridge_config_.our_bpdu_info; // Base parameters

                uint16_t msg_age_for_bpdu = params_for_bpdu.message_age;
                if (!bridge_config_.is_root_bridge()) {
                    // Per IEEE 802.1D-2004, page 108: Message Age on BPDUs transmitted through a Designated Port
                    // is incremented by one second for each second of the transit time through the Bridge.
                    // Simplified: add 1 second (256 units) to the received Message Age.
                    // This should be based on the *actual* message age from the root BPDU + transit.
                    // For a simple model, if our_bpdu_info.message_age is what we *received* from upstream,
                    // we add a small increment. If it's what *we calculated as root*, it's 0.
                     msg_age_for_bpdu += (1 * 256); // Increment by 1 second
                }

                if (msg_age_for_bpdu >= params_for_bpdu.max_age) {
                    logger.warn("STP_BPDU_GEN", "Msg age would exceed Max age for BPDU on port " + std::to_string(port_id));
                    continue;
                }

                bpdu_to_send_struct.from_bpdu_info_for_sending(
                    params_for_bpdu,                 // Contains Root ID, Root Path Cost from our perspective
                    bridge_config_.bridge_id_value,  // Our Bridge ID as Sender BID
                    p_info.stp_port_id_field,        // Our Port ID as Sender PID
                    msg_age_for_bpdu,                // Effective Message Age
                    params_for_bpdu.max_age,         // Max Age from (our view of) Root
                    params_for_bpdu.hello_time,      // Hello Time from (our view of) Root
                    params_for_bpdu.forward_delay    // Forward Delay from (our view of) Root
                );

                // TC/TCA flags are typically set based on topology change state machines, not directly from our_bpdu_info all the time.
                // For now, use flags from our_bpdu_info.
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
                // Correctly create MacAddress objects for assignment
                uint8_t stp_dst_mac_bytes[] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x00};
                eth_hdr->dst_mac = MacAddress(stp_dst_mac_bytes);

                // Convert uint64_t bridge_mac_address to uint8_t[6] for MacAddress constructor
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
                // Packet dtor will call release_buffer on pb
                // buffer_pool.release_buffer(pb); // This would be a double release if Packet owns it.

                logger.info("STP_BPDU_GEN", "Generated BPDU on port " + std::to_string(port_id));
            }
        }
    }
    return bpdus_to_send;
}

// --- StpManager::recalculate_stp_roles_and_states ---
void StpManager::recalculate_stp_roles_and_states(SwitchLogger& logger) {
    // Implementation based on previous detailed logic.
    // This will involve root bridge election, root port selection, designated port election,
    // and updating port roles and states.

    // 1. Assume self as root initially for this cycle's calculation
    ReceivedBpduInfo best_bpdu_for_root_election = bridge_config_.our_bpdu_info; // Start with current state
    // Ensure it reflects this bridge if it were root
    best_bpdu_for_root_election.root_id = bridge_config_.bridge_id_value;
    best_bpdu_for_root_election.root_path_cost = 0;
    best_bpdu_for_root_election.sender_bridge_id = bridge_config_.bridge_id_value;
    best_bpdu_for_root_election.sender_port_id = 0;
    best_bpdu_for_root_election.message_age = 0;
    best_bpdu_for_root_election.max_age = bridge_config_.max_age_seconds * 256;
    best_bpdu_for_root_election.hello_time = bridge_config_.hello_time_seconds * 256;
    best_bpdu_for_root_election.forward_delay = bridge_config_.forward_delay_seconds * 256;


    std::optional<uint32_t> new_root_port_id;

    // Iterate over all ports to find the best BPDU received, which determines the root
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
        logger.info("STP_RECALC", "This bridge (" + logger.uint64_to_hex_string(bridge_config_.bridge_id_value) + ") is ROOT.");
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
            logger.warn("STP_RECALC", "No path to known root " + logger.uint64_to_hex_string(bridge_config_.our_bpdu_info.root_id) + ". Reverting to self as root.");
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

    // Determine port roles and states
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
