#ifndef NETFLOW_STP_MANAGER_HPP
#define NETFLOW_STP_MANAGER_HPP

#include "packet.hpp" // For Packet class (BPDU is a type of packet)
#include <cstdint>
#include <vector>
#include <map>
#include <optional> // For get_port_state potentially returning optional or a default
#include <arpa/inet.h> // For htons, ntohs, etc.
#include <cstring> // For memcpy

namespace netflow {

#include <chrono> // For timers, if we use std::chrono

// Forward declaration for StpManager to be used in ConfigBpdu methods if needed.
class StpManager;

// Define constants for STP
namespace StpDefaults {
    const uint8_t PROTOCOL_ID = 0x00;
    const uint8_t VERSION_ID_STP = 0x00; // For STP/RSTP
    // Other versions like MSTP (0x02, 0x03) exist
    const uint8_t BPDU_TYPE_CONFIG = 0x00;
    const uint8_t BPDU_TYPE_TCN = 0x80;
}

// Structure to hold information from a received BPDU
struct ReceivedBpduInfo {
    uint64_t root_id = 0;
    uint32_t root_path_cost = 0;
    uint64_t sender_bridge_id = 0;
    uint16_t sender_port_id = 0; // 12 bits priority + 4 bits port number = 16 bits total in BPDU
    uint16_t message_age = 0;    // In 1/256th of a second
    uint16_t max_age = 0;        // In 1/256th of a second
    uint16_t hello_time = 0;     // In 1/256th of a second
    uint16_t forward_delay = 0;  // In 1/256th of a second
    bool tca_flag = false;       // Topology Change Ack
    bool tc_flag = false;        // Topology Change

    ReceivedBpduInfo() = default;

    // Heuristic to check if this BPDU is "better" than another
    // This is a simplified comparison logic. Real STP comparison is more nuanced.
    bool is_superior_to(const ReceivedBpduInfo& other, uint64_t current_bridge_id) const {
        if (root_id < other.root_id) return true;
        if (root_id > other.root_id) return false;

        if (root_path_cost < other.root_path_cost) return true;
        if (root_path_cost > other.root_path_cost) return false;

        if (sender_bridge_id < other.sender_bridge_id) return true;
        if (sender_bridge_id > other.sender_bridge_id) return false;

        // If sender is the same, prefer BPDU from a lower port ID on that sender
        if (sender_port_id < other.sender_port_id) return true;
        if (sender_port_id > other.sender_port_id) return false;

        // If all else is equal, prefer BPDU from the bridge that is *not* us, if one is from us
        // This helps break ties when comparing a BPDU from another bridge with our own information
        // if (sender_bridge_id != current_bridge_id && other.sender_bridge_id == current_bridge_id) return true;

        return false; // Otherwise, not strictly superior
    }

    bool is_from_root() const {
      return root_id == sender_bridge_id;
    }
};


// Structure for a standard Configuration BPDU (IEEE 802.1D)
// All multi-byte fields are transmitted MSB first (network byte order).
struct ConfigBpdu {
    uint8_t protocol_id;       // Byte 0: Must be 0x00 for STP
    uint8_t version_id;        // Byte 1: Must be 0x00 for STP/RSTP
    uint8_t bpdu_type;         // Byte 2: Must be 0x00 for Configuration BPDU
    uint8_t flags;             // Byte 3: TCA (0x80), TC (0x01)
    uint64_t root_id;          // Bytes 4-11: Bridge ID of the current root
    uint32_t root_path_cost;   // Bytes 12-15: Cost to reach the root from transmitting bridge
    uint64_t bridge_id;        // Bytes 16-23: Bridge ID of the transmitting bridge
    uint16_t port_id;          // Bytes 24-25: Port ID of the transmitting port
    uint16_t message_age;      // Bytes 26-27: Age of BPDU info (in 1/256 s)
    uint16_t max_age;          // Bytes 28-29: Max age for BPDU info (in 1/256 s)
    uint16_t hello_time;       // Bytes 30-31: Hello time (in 1/256 s)
    uint16_t forward_delay;    // Bytes 32-33: Forward delay (in 1/256 s)
    // Version 1 BPDU ends here (34 bytes from protocol_id)
    // Version 2 (RSTP) adds more fields if bpdu_type indicates RSTP. Total 35 bytes for Config BPDU.
    // For basic STP, we can consider the length to be 35 bytes including a version 1 length field (implicitly).
    // The actual BPDU length on wire is 35 bytes.
    // The struct size should be 34 bytes if we don't count the implicit v1_length field.
    // Let's assume the raw BPDU data starts with protocol_id and is at least 34 bytes.
    // The IEEE standard shows the "Version 1 Length" field as byte 34, value 0.

    ConfigBpdu() : protocol_id(StpDefaults::PROTOCOL_ID), version_id(StpDefaults::VERSION_ID_STP),
                   bpdu_type(StpDefaults::BPDU_TYPE_CONFIG), flags(0),
                   root_id(0), root_path_cost(0), bridge_id(0), port_id(0),
                   message_age(0), max_age(0), hello_time(0), forward_delay(0) {}

    // Method to populate from ReceivedBpduInfo (used for sending our own BPDUs)
    // Note: StpManager::BridgeConfig is not fully defined here yet if this struct is outside/before StpManager
    // For now, let's assume direct values are passed or StpManager::BridgeConfig is forward-declared/accessible.
    void from_bpdu_info_for_sending(const ReceivedBpduInfo& source_info, uint64_t my_bridge_id, uint16_t my_port_id,
                                    uint16_t effective_message_age, uint16_t root_max_age, uint16_t root_hello_time, uint16_t root_forward_delay) {
        protocol_id = StpDefaults::PROTOCOL_ID;
        version_id = StpDefaults::VERSION_ID_STP;
        bpdu_type = StpDefaults::BPDU_TYPE_CONFIG;
        root_id = htonll(source_info.root_id);
        root_path_cost = htonl(source_info.root_path_cost);
        bridge_id = htonll(my_bridge_id);
        port_id = htons(my_port_id);
        message_age = htons(effective_message_age); // Message age can be 0 if we are root, or incremented from root's BPDU
        max_age = htons(root_max_age);
        hello_time = htons(root_hello_time);
        forward_delay = htons(root_forward_delay);
        flags = (source_info.tc_flag ? 0x01 : 0x00) | (source_info.tca_flag ? 0x80 : 0x00);
    }

    // Populate BpduInfo from this BPDU structure (after receiving and parsing)
    ReceivedBpduInfo to_received_bpdu_info() const {
        ReceivedBpduInfo info;
        // Ensure an incoming BPDU is valid before calling this
        if (protocol_id != StpDefaults::PROTOCOL_ID || version_id != StpDefaults::VERSION_ID_STP || bpdu_type != StpDefaults::BPDU_TYPE_CONFIG) {
            // Return a "bad" BPDU info if header is wrong
            info.root_id = 0xFFFFFFFFFFFFFFFFULL;
            return info;
        }
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

    // Custom htonll/ntohll for 64-bit integers if not standard
    static uint64_t htonll(uint64_t val) {
        if (__BYTE_ORDER == __LITTLE_ENDIAN) {
            return (((uint64_t)htonl(val & 0xFFFFFFFF)) << 32) | htonl(val >> 32);
        }
        return val;
    }
    static uint64_t ntohll(uint64_t val) {
        if (__BYTE_ORDER == __LITTLE_ENDIAN) {
            return (((uint64_t)ntohl(val & 0xFFFFFFFF)) << 32) | ntohl(val >> 32);
        }
        return val;
    }
};
const size_t CONFIG_BPDU_PAYLOAD_SIZE = 34; // Size of the ConfigBpdu struct (Protocol ID to Forward Delay)


class StpManager {
public:
    // Forward declare BridgeConfig so ConfigBpdu can use it if it were a member
    struct BridgeConfig;

    enum class PortRole {
        UNKNOWN,    // Not yet determined or port inactive in STP
        ROOT,       // Provides the best path to the Root Bridge
        DESIGNATED, // Forwarding port for a LAN segment (elected per segment)
        ALTERNATE,  // Offers an alternate path to the Root Bridge (backup for Root Port)
        BACKUP,     // Backup for a Designated Port (rare, e.g., hub connection)
        DISABLED    // Not participating in STP (administratively or due to failure)
    };

    enum class PortState {
        UNKNOWN,  // Default state, or if port is not managed by STP
        DISABLED, // Port is administratively down or STP disabled it
        BLOCKING, // Port does not forward traffic, but receives BPDUs (Alternate/Backup roles are Blocking)
        LISTENING, // Transitional state: not forwarding, not learning MACs, processing BPDUs
        LEARNING,  // Transitional state: not forwarding, but learning MACs, processing BPDUs
        FORWARDING // Port forwards traffic and processes BPDUs (Root/Designated roles can be Forwarding)
    };

    struct StpPortInfo {
        uint32_t port_id_internal; // The switch-local port ID (e.g., 0, 1, 2...)
        uint16_t stp_port_id_field; // The 16-bit value used in BPDUs (4bit priority + 12bit ID)
        PortRole role = PortRole::DISABLED;
        PortState state = PortState::DISABLED;
        uint32_t path_cost_to_segment = 19; // Cost of this port link (e.g. 10Gbps=2, 1Gbps=4, 100Mbps=19)

        // Information about the designated bridge and port for the segment connected to this port
        uint64_t designated_bridge_id_for_segment = 0;
        uint16_t designated_port_id_for_segment = 0;
        uint32_t path_cost_from_designated_bridge_to_root = 0xFFFFFFFF; // RPC of the DB for the segment

        // Timers for STP operation on this port
        uint16_t message_age_timer_seconds = 0; // Counts up to max_age (in seconds) for received BPDU info
        uint16_t forward_delay_timer_seconds = 0; // For Listening/Learning states (in seconds)
        uint16_t hello_timer_seconds = 0;      // For sending BPDUs on designated ports (in seconds)

        ReceivedBpduInfo received_bpdu; // Best BPDU *received* on this port
        bool new_bpdu_received_flag = false;
        uint8_t port_priority = 128; // Default port priority (0-240, in steps of 16)

        StpPortInfo(uint32_t id = 0) : port_id_internal(id) {
            // Initialize received_bpdu with "worst possible" values
            received_bpdu.root_id = 0xFFFFFFFFFFFFFFFFULL;
            received_bpdu.root_path_cost = 0xFFFFFFFF;
            received_bpdu.sender_bridge_id = 0xFFFFFFFFFFFFFFFFULL;
            received_bpdu.sender_port_id = 0xFFFF;
            update_stp_port_id_field();
        }

        void update_stp_port_id_field() {
            stp_port_id_field = static_cast<uint16_t>(((port_priority & 0xF0) << 8) | (port_id_internal & 0x0FFF));
        }

        bool has_valid_bpdu_info(uint16_t max_age_limit_seconds) const {
            return message_age_timer_seconds < max_age_limit_seconds && received_bpdu.sender_bridge_id != 0xFFFFFFFFFFFFFFFFULL;
        }

        // Total path cost to root via this port (segment cost + cost from DB to root)
        uint32_t get_total_path_cost_to_root_via_port() const {
            if (path_cost_from_designated_bridge_to_root == 0xFFFFFFFF) return 0xFFFFFFFF;
            return path_cost_to_segment + path_cost_from_designated_bridge_to_root;
        }
    };

    struct BridgeConfig {
        uint64_t bridge_mac_address = 0x000000000000ULL;
        uint16_t bridge_priority = 0x8000;
        uint64_t bridge_id_value;

        uint32_t hello_time_seconds = 2;
        uint32_t forward_delay_seconds = 15;
        uint32_t max_age_seconds = 20;

        // Our bridge's current view of the STP topology
        ReceivedBpduInfo our_bpdu_info; // This is the BPDU info this bridge would send if it's a designated bridge
                                        // or the info it believes about the root.
                                        // - root_id: ID of the root bridge we know.
                                        // - root_path_cost: Our cost to that root.
                                        // - sender_bridge_id: Our own bridge_id_value.
                                        // - sender_port_id: 0 if we are root, or our root port's stp_port_id_field.
                                        // - message_age, max_age, hello_time, forward_delay: timers from the root, or our own if we are root.

        std::optional<uint32_t> root_port_internal_id; // Our port that is the Root Port

        BridgeConfig(uint64_t mac = 0x000000000001ULL, uint16_t priority = 0x8000,
                     uint32_t hello = 2, uint32_t fwd_delay = 15, uint32_t age = 20)
            : bridge_mac_address(mac), bridge_priority(priority),
              hello_time_seconds(hello), forward_delay_seconds(fwd_delay), max_age_seconds(age) {
            update_bridge_id_value();
            // Initially, assume self is root
            our_bpdu_info.root_id = bridge_id_value;
            our_bpdu_info.root_path_cost = 0;
            our_bpdu_info.sender_bridge_id = bridge_id_value;
            our_bpdu_info.sender_port_id = 0; // Port ID is 0 for BPDUs originated by the root itself
            our_bpdu_info.message_age = 0;
            our_bpdu_info.max_age = max_age_seconds * 256;
            our_bpdu_info.hello_time = hello_time_seconds * 256;
            our_bpdu_info.forward_delay = forward_delay_seconds * 256;
            our_bpdu_info.tc_flag = false;
            our_bpdu_info.tca_flag = false;
        }

        void update_bridge_id_value() {
            bridge_id_value = (static_cast<uint64_t>(bridge_priority) << 48) | (bridge_mac_address & 0x0000FFFFFFFFFFFFULL);
        }

        bool is_root_bridge() const {
            return our_bpdu_info.root_id == bridge_id_value;
        }
    };

    StpManager(uint32_t num_ports, uint64_t switch_mac_address, uint16_t switch_priority = 0x8000)
        : bridge_config_(switch_mac_address, switch_priority) {
        initialize_ports(num_ports);
        recalculate_stp_roles_and_states(); // Initial calculation
    }

    void initialize_ports(uint32_t num_ports) {
        port_stp_info_.clear();
        for (uint32_t i = 0; i < num_ports; ++i) {
            port_stp_info_[i] = StpPortInfo(i);
            // Set initial state to BLOCKING, role to UNKNOWN (will be determined)
            // Or DISABLED if ports are admin down by default from elsewhere.
            // For now, assume ports become active in STP unless admin down.
            port_stp_info_[i].state = PortState::BLOCKING;
            port_stp_info_[i].role = PortRole::UNKNOWN;

            // Initialize received BPDU for each port to reflect no valid BPDU received yet.
            // This means it will initially consider itself as designated for its segments.
            port_stp_info_[i].received_bpdu.root_id = bridge_config_.bridge_id_value; // Treat as if we sent a BPDU to ourselves
            port_stp_info_[i].received_bpdu.root_path_cost = 0;
            port_stp_info_[i].received_bpdu.sender_bridge_id = bridge_config_.bridge_id_value;
            port_stp_info_[i].received_bpdu.sender_port_id = port_stp_info_[i].stp_port_id_field;
            port_stp_info_[i].received_bpdu.message_age = 0;
            port_stp_info_[i].received_bpdu.max_age = bridge_config_.our_bpdu_info.max_age;
            port_stp_info_[i].received_bpdu.hello_time = bridge_config_.our_bpdu_info.hello_time;
            port_stp_info_[i].received_bpdu.forward_delay = bridge_config_.our_bpdu_info.forward_delay;

            // Default path cost per port, should be configurable based on actual port speed
            port_stp_info_[i].path_cost_to_segment = 19; // Example: 100Mbps.
        }
    }


    void set_bridge_mac_address_and_reinit(uint64_t mac) { // Renamed to clarify re-init
        bridge_config_.bridge_mac_address = mac;
        bridge_config_.update_bridge_id_value();

        // Bridge ID changed, must re-evaluate everything from scratch for STP.
        // Assume self is root again initially.
        bridge_config_.our_bpdu_info.root_id = bridge_config_.bridge_id_value;
        bridge_config_.our_bpdu_info.root_path_cost = 0;
        bridge_config_.our_bpdu_info.sender_bridge_id = bridge_config_.bridge_id_value;
        bridge_config_.our_bpdu_info.sender_port_id = 0;
        bridge_config_.our_bpdu_info.message_age = 0;
        // Timers (max_age, hello, fwd_delay) in our_bpdu_info remain from config.
        bridge_config_.root_port_internal_id.reset();

        // Re-initialize port-specific BPDU info as if we are the root for all segments initially
        for (auto& pair : port_stp_info_) {
            StpPortInfo& p_info = pair.second;
            p_info.received_bpdu.root_id = bridge_config_.bridge_id_value;
            p_info.received_bpdu.root_path_cost = 0;
            p_info.received_bpdu.sender_bridge_id = bridge_config_.bridge_id_value;
            p_info.received_bpdu.sender_port_id = p_info.stp_port_id_field;
            p_info.received_bpdu.message_age = 0;
            // Reset timers
            p_info.message_age_timer_seconds = 0;
            p_info.forward_delay_timer_seconds = 0;
            p_info.hello_timer_seconds = 0;
        }
        recalculate_stp_roles_and_states();
    }

    void set_bridge_priority_and_reinit(uint16_t priority) { // Renamed
        bridge_config_.bridge_priority = priority;
        // Call the same re-initialization logic
        set_bridge_mac_address_and_reinit(bridge_config_.bridge_mac_address);
    }

    const BridgeConfig& get_bridge_config() const {
        return bridge_config_;
    }

    void admin_set_port_state(uint32_t port_id, bool enable) {
        auto it = port_stp_info_.find(port_id);
        if (it != port_stp_info_.end()) {
            if (!enable) { // Disabling port
                 it->second.state = PortState::DISABLED;
                 it->second.role = PortRole::DISABLED;
                 // Reset timers and BPDU info
                 it->second.message_age_timer_seconds = 0;
                 it->second.forward_delay_timer_seconds = 0;
                 it->second.hello_timer_seconds = 0;
                 it->second.received_bpdu = ReceivedBpduInfo(); // Clear received BPDU
                 it->second.received_bpdu.root_id = 0xFFFFFFFFFFFFFFFFULL;
            } else { // Enabling port
                if (it->second.state == PortState::DISABLED) { // Only if it was disabled
                    it->second.state = PortState::BLOCKING;
                    it->second.role = PortRole::UNKNOWN;
                    it->second.message_age_timer_seconds = 0;
                    it->second.forward_delay_timer_seconds = 0;
                    it->second.hello_timer_seconds = 0;
                    // Initialize received BPDU to reflect self as root for this port's segment initially
                    it->second.received_bpdu.root_id = bridge_config_.bridge_id_value;
                    it->second.received_bpdu.root_path_cost = 0;
                    it->second.received_bpdu.sender_bridge_id = bridge_config_.bridge_id_value;
                    it->second.received_bpdu.sender_port_id = it->second.stp_port_id_field;
                    it->second.received_bpdu.message_age = 0;
                    it->second.received_bpdu.max_age = bridge_config_.our_bpdu_info.max_age;
                    it->second.received_bpdu.hello_time = bridge_config_.our_bpdu_info.hello_time;
                    it->second.received_bpdu.forward_delay = bridge_config_.our_bpdu_info.forward_delay;
                }
            }
            recalculate_stp_roles_and_states(); // STP recalculation needed
        }
    }

    PortState get_port_stp_state(uint32_t port_id) const {
        auto it = port_stp_info_.find(port_id);
        if (it != port_stp_info_.end()) {
            return it->second.state;
        }
        return PortState::UNKNOWN;
    }

    PortRole get_port_stp_role(uint32_t port_id) const {
        auto it = port_stp_info_.find(port_id);
        if (it != port_stp_info_.end()) {
            return it->second.role;
        }
        return PortRole::UNKNOWN;

    // Determines if a port should forward user traffic based on its STP state.
    bool should_forward(uint32_t port_id) const {
        return get_port_state(port_id) == PortState::FORWARDING;
    }

    // Determines if a port should learn MAC addresses.
    bool should_learn(uint32_t port_id) const {
        PortState state = get_port_state(port_id);
        return state == PortState::LEARNING || state == PortState::FORWARDING;
    }

    // Main STP logic method
    void recalculate_stp_roles_and_states(); // Definition in .cpp

    void process_bpdu(const Packet& bpdu_packet, uint32_t ingress_port_id); // Definition in .cpp

    // generate_bpdus now needs BufferPool access
    std::vector<Packet> generate_bpdus(BufferPool& buffer_pool); // Definition in .cpp

    void run_stp_timers() {
        bool needs_recalculation = false;
        for (auto& pair : port_stp_info_) {
            StpPortInfo& p_info = pair.second;
            if (p_info.state == PortState::DISABLED) {
                p_info.message_age_timer_seconds = 0; // Reset timers if disabled
                p_info.forward_delay_timer_seconds = 0;
                p_info.hello_timer_seconds = 0;
                continue;
            }

            // Message Age Timer for received BPDUs on this port
            // This timer tracks the validity of the BPDU info received on p_info.
            // It's reset when a new BPDU arrives on this port.
            // It increments when the BPDU's own message_age would increment if relayed.
            // Here, we use it to age out the p_info.received_bpdu if no new BPDU refreshes it.
            if (p_info.received_bpdu.sender_bridge_id != 0xFFFFFFFFFFFFFFFFULL) { // If we have some BPDU info
                 p_info.message_age_timer_seconds++; // Increment each second this timer runs
                if (p_info.message_age_timer_seconds >= (p_info.received_bpdu.max_age / 256)) { // Compare with Max Age from the BPDU
                    // BPDU information aged out on this port
                    p_info.received_bpdu = ReceivedBpduInfo();
                    p_info.received_bpdu.root_id = 0xFFFFFFFFFFFFFFFFULL;
                    p_info.received_bpdu.sender_bridge_id = 0xFFFFFFFFFFFFFFFFULL;
                    p_info.message_age_timer_seconds = 0; // Reset timer
                    needs_recalculation = true;
                }
            }

            // Forward Delay Timer for Listening/Learning states for Root or Designated ports
            if (p_info.role == PortRole::ROOT || p_info.role == PortRole::DESIGNATED) {
                if (p_info.state == PortState::LISTENING || p_info.state == PortState::LEARNING) {
                    p_info.forward_delay_timer_seconds++;
                    if (p_info.forward_delay_timer_seconds >= bridge_config_.forward_delay_seconds) {
                        p_info.forward_delay_timer_seconds = 0;
                        if (p_info.state == PortState::LISTENING) {
                            p_info.state = PortState::LEARNING;
                        } else if (p_info.state == PortState::LEARNING) {
                            p_info.state = PortState::FORWARDING;
                        }
                        needs_recalculation = true;
                    }
                }
            } else { // Non-Root/Non-Designated ports should be BLOCKING or DISABLED
                if (p_info.state == PortState::LISTENING || p_info.state == PortState::LEARNING) {
                    p_info.state = PortState::BLOCKING;
                    p_info.forward_delay_timer_seconds = 0;
                    needs_recalculation = true;
                }
            }

            // Hello timer for designated ports to trigger BPDU generation
            if (p_info.role == PortRole::DESIGNATED &&
                (p_info.state == PortState::FORWARDING || p_info.state == PortState::LEARNING || p_info.state == PortState::LISTENING)) {
                p_info.hello_timer_seconds++;
                // generate_bpdus() will check this timer and reset it if BPDU is sent.
            }
        }

        if (needs_recalculation) {
            recalculate_stp_roles_and_states();
        }
    }

private:
    BridgeConfig bridge_config_;
    std::map<uint32_t, StpPortInfo> port_stp_info_;

public:
    std::string port_state_to_string(PortState state) const {
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
    std::string port_role_to_string(PortRole role) const {
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

    // Add a method to get a summary of all port states/roles for logging
    std::map<uint32_t, std::pair<std::string, std::string>> get_all_ports_stp_info_summary() const {
        std::map<uint32_t, std::pair<std::string, std::string>> summary;
        for(const auto& pair_info : port_stp_info_) {
            summary[pair_info.first] = {port_role_to_string(pair_info.second.role), port_state_to_string(pair_info.second.state)};
        }
        return summary;
    }

};

} // namespace netflow

#endif // NETFLOW_STP_MANAGER_HPP
