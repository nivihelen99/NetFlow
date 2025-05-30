#ifndef NETFLOW_LACP_MANAGER_HPP
#define NETFLOW_LACP_MANAGER_HPP

#include <cstdint>
#include <vector>
#include <map>
#include <optional>
#include <algorithm> // For std::sort, std::unique, std::remove
#include <string>    // Potentially for names or logging
#include <iostream>  // For placeholder logging

#include "packet.hpp" // For Packet class, used in select_egress_port and process_lacpdu
#include <arpa/inet.h> // For htons, ntohs
#include <cstring> // For memcpy

// Forward declare PacketClassifier if its FlowKey might be used directly for hashing inspiration
// namespace netflow { class PacketClassifier; }

// LACP Constants
namespace LacpDefaults {
    const uint8_t LACP_SUBTYPE = 0x01;
    const uint8_t LACP_VERSION = 0x01;
    const uint64_t LACP_MULTICAST_MAC = 0x0180C2000002ULL; // Standard LACP multicast MAC
    const uint16_t LACP_ETHERTYPE = 0x8809;
}


namespace netflow {

// LACP State flags for Actor and Partner State fields
// These are bitmasks for an 8-bit field.
enum LacpStateFlag : uint8_t {
    LACP_ACTIVITY     = 0x01, // Active LACP (1) or Passive LACP (0)
    LACP_TIMEOUT      = 0x02, // Short timeout (1) or Long timeout (0)
    AGGREGATION       = 0x04, // Port is aggregatable (1) or individual (0)
    SYNCHRONIZATION   = 0x08, // Port is in sync (1) or out of sync (0)
    COLLECTING        = 0x10, // Enables packet collection (1) or disables (0)
    DISTRIBUTING      = 0x20, // Enables packet distribution (1) or disables (0)
    DEFAULTED         = 0x40, // Using defaulted partner info (1) or operational partner info (0)
    EXPIRED           = 0x80  // LACP PDU expired (1) or not expired (0)
};

// LACPDU Structure (based on IEEE 802.1AX Section 7.4.2)
// All fields are transmitted in network byte order (Big Endian).
struct Lacpdu {
    uint8_t subtype;            // 0: Byte 0 - Must be 0x01 for LACP
    uint8_t version_number;     // 1: Byte 1 - Must be 0x01 for this version

    // Actor Information (TLV type 0x01, Length 0x14 = 20 bytes)
    uint8_t tlv_type_actor;     // 2: Byte 2 - Actor Info TLV type (0x01)
    uint8_t actor_info_length;  // 3: Byte 3 - Length of Actor Info (0x14 = 20)
    uint16_t actor_system_priority; // 4-5: Bytes 4-5
    uint8_t actor_system_mac[6];   // 6-11: Bytes 6-11
    uint16_t actor_key;          // 12-13: Bytes 12-13
    uint16_t actor_port_priority;// 14-15: Bytes 14-15
    uint16_t actor_port_number;  // 16-17: Bytes 16-17
    uint8_t actor_state;        // 18: Byte 18 - Bitmask of LacpStateFlag
    uint8_t reserved_actor[3];  // 19-21: Reserved, must be 0

    // Partner Information (TLV type 0x02, Length 0x14 = 20 bytes)
    uint8_t tlv_type_partner;   // 22: Byte 22 - Partner Info TLV type (0x02)
    uint8_t partner_info_length;// 23: Byte 23 - Length of Partner Info (0x14 = 20)
    uint16_t partner_system_priority; // 24-25
    uint8_t partner_system_mac[6];   // 26-31
    uint16_t partner_key;          // 32-33
    uint16_t partner_port_priority;// 34-35
    uint16_t partner_port_number;  // 36-37
    uint8_t partner_state;        // 38
    uint8_t reserved_partner[3]; // 39-41

    // Collector Information (TLV type 0x03, Length 0x10 = 16 bytes)
    uint8_t tlv_type_collector; // 42
    uint8_t collector_info_length; // 43 (0x10 = 16)
    uint16_t collector_max_delay; // 44-45
    uint8_t reserved_collector[12]; // 46-57

    // Terminator Information (TLV type 0x00, Length 0x00)
    uint8_t tlv_type_terminator; // 58
    uint8_t terminator_length;   // 59 (0x00)
    uint8_t reserved_terminator[50]; // Optional padding for some hardware, up to 110 bytes total LACPDU.
                                     // Standard LACPDU is 60 bytes up to terminator_length.
                                     // Max LACPDU size is typically 124 bytes (including subtype & version).
                                     // We will use the minimum size of 60 bytes for now.

    Lacpdu() {
        std::memset(this, 0, sizeof(Lacpdu));
        subtype = LacpDefaults::LACP_SUBTYPE;
        version_number = LacpDefaults::LACP_VERSION;
        tlv_type_actor = 0x01; actor_info_length = 0x14;
        tlv_type_partner = 0x02; partner_info_length = 0x14;
        tlv_type_collector = 0x03; collector_info_length = 0x10;
        tlv_type_terminator = 0x00; terminator_length = 0x00;
    }

    // Note: Serialization/deserialization needs to handle network byte order for multi-byte fields.
    // For simplicity, direct memcpy can be used if struct is packed and host/network order match or fields are single bytes.
    // However, portable code requires explicit ntohs/htons and ntohll/htonll (custom for 64-bit System ID if used).
    // For now, we assume direct struct copy and handle byte order during field access/population if needed.
    // Example: actor_system_priority = htons(host_priority_val); host_priority_val = ntohs(actor_system_priority);

    uint64_t get_actor_system_id() const {
        uint64_t mac_part = 0;
        for(int i=0; i<6; ++i) mac_part = (mac_part << 8) | actor_system_mac[i];
        return (static_cast<uint64_t>(ntohs(actor_system_priority)) << 48) | mac_part;
    }

    void set_actor_system_id(uint64_t system_id) {
        actor_system_priority = htons(static_cast<uint16_t>((system_id >> 48) & 0xFFFF));
        for(int i=0; i<6; ++i) actor_system_mac[5-i] = (system_id >> (i*8)) & 0xFF;
    }
    // Similar get/set for partner_system_id
};
const size_t LACPDU_MIN_SIZE = 60; // Minimum size including terminator TLV header


enum class LacpHashMode {
    SRC_MAC,
    DST_MAC,
    SRC_DST_MAC,        // L2 hash
    SRC_IP,
    DST_IP,
    SRC_DST_IP,         // L3 hash
    SRC_PORT,
    DST_PORT,
    SRC_DST_PORT,       // L4 hash
    SRC_DST_IP_L4_PORT  // Common 5-tuple hash
};

struct LagConfig {
    uint32_t lag_id = 0;
    std::vector<uint32_t> member_ports;
    LacpHashMode hash_mode = LacpHashMode::SRC_DST_IP_L4_PORT;
    bool active_mode = true;  // LACP mode: true for Active (proactively send LACPDUs), false for Passive
    uint16_t lacp_rate = 1; // 0 for Slow (30s), 1 for Fast (1s) - This is our desired rate for actor.

    // Actor System Configuration for this LAG (used by all member ports)
    // uint16_t actor_system_priority = 32768; // Set globally in LacpManager
    // uint64_t actor_system_mac_id;      // Set globally in LacpManager
    uint16_t actor_admin_key = 0; // Admin configured key for this LAG

    LagConfig() = default;
};


struct LacpPortInfo {
    uint32_t port_id_physical; // Switch's physical port ID

    // Actor Info (This port's information)
    uint64_t actor_system_id_val = 0; // Combines priority + MAC
    uint16_t actor_port_id_val = 0;   // Combines priority + physical port number
    uint16_t actor_key_val = 0;
    uint8_t actor_state_val = 0;      // Bitmask of LacpStateFlag

    // Partner Info (Information about the port on the other end of the link)
    uint64_t partner_system_id_val = 0;
    uint16_t partner_port_id_val = 0;
    uint16_t partner_key_val = 0;
    uint8_t partner_state_val = 0;

    bool is_active_member_of_lag = false; // True if selected and part of an active aggregator
    uint32_t current_aggregator_id = 0; // LAG ID this port is currently bound to, if any

    // Timers (value in seconds or ticks, to be decided by timer implementation)
    uint16_t current_while_timer_ticks = 0; // For periodic LACPDU transmission
    uint16_t short_timeout_timer_ticks = 0; // If partner is using short timeout
    uint16_t long_timeout_timer_ticks = 0;  // If partner is using long timeout
    // Other timers like wait_while_timer might be needed for specific state transitions

    enum class MuxMachineState { DETACHED, WAITING, ATTACHED, COLLECTING_DISTRIBUTING };
    MuxMachineState mux_state = MuxMachineState::DETACHED;

    enum class RxMachineState { INITIALIZE, PORT_DISABLED, LACP_DISABLED, EXPIRED, DEFAULTED, CURRENT };
    RxMachineState rx_state = RxMachineState::INITIALIZE;

    enum class PeriodicTxState { NO_PERIODIC, FAST_PERIODIC, SLOW_PERIODIC, PERIODIC_TX };
    PeriodicTxState periodic_tx_state = PeriodicTxState::NO_PERIODIC;

    uint16_t port_priority_val = 128; // LACP port priority (0-255, lower is better for tie-breaking selection)
                                     // Default to a mid-range value.

    LacpPortInfo(uint32_t phys_id = 0) : port_id_physical(phys_id) {}

    void set_actor_state_flag(LacpStateFlag flag, bool set) {
        if (set) actor_state_val |= static_cast<uint8_t>(flag);
        else actor_state_val &= ~static_cast<uint8_t>(flag);
    }
    bool get_actor_state_flag(LacpStateFlag flag) const {
        return (actor_state_val & static_cast<uint8_t>(flag)) != 0;
    }
    // Similar helpers for partner_state_val if needed
};


class LacpManager {
public:
    // Constructor needs switch's base MAC and system priority for LACP System ID
    LacpManager(uint64_t switch_base_mac, uint16_t system_priority = 32768)
        : switch_mac_address_(switch_base_mac), lacp_system_priority_(system_priority) {
        actor_system_id_ = (static_cast<uint64_t>(lacp_system_priority_) << 48) | (switch_mac_address_ & 0x0000FFFFFFFFFFFFULL);
    }

    bool create_lag(LagConfig& config) { // Pass by non-const ref to update its key if needed
        if (config.lag_id == 0) {
            return false;
        }
        if (lags_.count(config.lag_id)) {
            return false;
        }

        // Check if any proposed member ports are already in other LAGs
        for (uint32_t port_id : config.member_ports) {
            if (port_to_lag_map_.count(port_id)) {
                return false;
            }
        }

        // If admin key is 0, use lag_id as key (common practice)
        if (config.actor_admin_key == 0) {
            config.actor_admin_key = static_cast<uint16_t>(config.lag_id & 0xFFFF);
        }

        lags_[config.lag_id] = config;
        auto& stored_config = lags_[config.lag_id];
        std::sort(stored_config.member_ports.begin(), stored_config.member_ports.end());
        stored_config.member_ports.erase(
            std::unique(stored_config.member_ports.begin(), stored_config.member_ports.end()),
            stored_config.member_ports.end()
        );

        for (uint32_t port_id : stored_config.member_ports) {
            port_to_lag_map_[port_id] = config.lag_id;
            initialize_lacp_port_info(port_id, config);
        }
        return true;
    }

    // Adds a physical port to an existing LAG.
    bool add_port_to_lag(uint32_t lag_id, uint32_t port_id) {
        auto lag_it = lags_.find(lag_id);
        if (lag_it == lags_.end()) {
            return false;
        }

        auto port_map_it = port_to_lag_map_.find(port_id);
        if (port_map_it != port_to_lag_map_.end()) {
            if (port_map_it->second == lag_id) return true;
            return false;
        }

        lag_it->second.member_ports.push_back(port_id);
        std::sort(lag_it->second.member_ports.begin(), lag_it->second.member_ports.end());
        lag_it->second.member_ports.erase(
            std::unique(lag_it->second.member_ports.begin(), lag_it->second.member_ports.end()),
            lag_it->second.member_ports.end()
        );
        port_to_lag_map_[port_id] = lag_id;
        initialize_lacp_port_info(port_id, lag_it->second);
        return true;
    }

    // Removes a physical port from a LAG.
    bool remove_port_from_lag(uint32_t lag_id, uint32_t port_id) {
        auto lag_it = lags_.find(lag_id);
        if (lag_it == lags_.end()) {
            return false;
        }

        auto port_map_it = port_to_lag_map_.find(port_id);
        if (port_map_it == port_to_lag_map_.end() || port_map_it->second != lag_id) {
            return false;
        }

        auto& members = lag_it->second.member_ports;
        members.erase(std::remove(members.begin(), members.end(), port_id), members.end());
        port_to_lag_map_.erase(port_id);
        port_lacp_info_.erase(port_id); // Remove LACP specific info for the port

        if (members.empty()) {
            // Consider logging "LAG has no more members"
        }
        return true;
    }

    void delete_lag(uint32_t lag_id) {
        auto lag_it = lags_.find(lag_id);
        if (lag_it != lags_.end()) {
            for (uint32_t port_id : lag_it->second.member_ports) {
                port_to_lag_map_.erase(port_id);
                port_lacp_info_.erase(port_id);
            }
            lags_.erase(lag_id);
        }
    }

    // select_egress_port will be refined later
    uint32_t select_egress_port(uint32_t lag_id, const Packet& pkt) const;

    void process_lacpdu(const Packet& lacpdu_packet, uint32_t ingress_port_id); // Implemented in .cpp

    std::vector<Packet> generate_lacpdus(BufferPool& buffer_pool); // Implemented in .cpp

    void run_lacp_timers_and_statemachines(); // Combines timer checks and state machine execution

private:
    void initialize_lacp_port_info(uint32_t port_id, const LagConfig& lag_config) {
        LacpPortInfo& p_info = port_lacp_info_[port_id];
        p_info.port_id_physical = port_id;

        p_info.actor_system_id_val = actor_system_id_;
        // Actor port ID: high 8 bits priority, low 8 bits physical port number
        p_info.actor_port_id_val = (static_cast<uint16_t>(p_info.port_priority_val) << 8) | (port_id & 0xFF);
        p_info.actor_key_val = lag_config.actor_admin_key; // Use LAG's admin key as operational key initially

        p_info.set_actor_state_flag(LACP_ACTIVITY, lag_config.active_mode);
        p_info.set_actor_state_flag(LACP_TIMEOUT, lag_config.lacp_rate == 1); // Fast timeout if rate is 1
        p_info.set_actor_state_flag(AGGREGATION, true); // Port is always aggregatable if part of LAG
        p_info.set_actor_state_flag(SYNCHRONIZATION, false); // Initially out of sync
        p_info.set_actor_state_flag(COLLECTING, false);
        p_info.set_actor_state_flag(DISTRIBUTING, false);
        p_info.set_actor_state_flag(DEFAULTED, true); // Partner info is defaulted initially
        p_info.set_actor_state_flag(EXPIRED, false);  // Own info is not expired

        // Initialize partner info to defaults (zero or "worst case")
        p_info.partner_system_id_val = 0;
        p_info.partner_port_id_val = 0;
        p_info.partner_key_val = 0;
        p_info.partner_state_val = LacpStateFlag::DEFAULTED | LacpStateFlag::EXPIRED; // Defaulted and Expired

        p_info.mux_state = LacpPortInfo::MuxMachineState::DETACHED;
        p_info.rx_state = LacpPortInfo::RxMachineState::INITIALIZE; // Will transition based on port status
        p_info.periodic_tx_state = LacpPortInfo::PeriodicTxState::NO_PERIODIC; // Will transition
    }

    // State machine helper methods (to be defined in .cpp)
    void run_lacp_rx_machine(uint32_t port_id);
    void run_lacp_periodic_tx_machine(uint32_t port_id);
    void run_lacp_mux_machine(uint32_t port_id);
    // Other machines like Churn Detection might be added.

public: // Temp public for main to call, ideally private or part of run_lacp_timers
    void update_port_selection_logic(uint32_t port_id); // Placeholder for selection logic part of MUX


    // Checks if a physical port is part of any LAG.
    bool is_port_in_lag(uint32_t port_id) const {
        return port_to_lag_map_.count(port_id);
    }

    // Gets the LAG ID for a given physical port, if it's part of one.
    std::optional<uint32_t> get_lag_for_port(uint32_t port_id) const {
        auto it = port_to_lag_map_.find(port_id);
        if (it != port_to_lag_map_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    // Retrieves the configuration for a specific LAG.
    std::optional<LagConfig> get_lag_config(uint32_t lag_id) const {
        auto it = lags_.find(lag_id);
        if (it != lags_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    // Retrieves all configured LAGs
    const std::map<uint32_t, LagConfig>& get_all_lags() const {
        return lags_;
    }

private:
    uint64_t switch_mac_address_; // Base MAC for the switch
    uint16_t lacp_system_priority_; // LACP system priority for the switch
    uint64_t actor_system_id_;      // Combined system_priority + switch_mac_address

    std::map<uint32_t, LagConfig> lags_;
    std::map<uint32_t, uint32_t> port_to_lag_map_;
    std::map<uint32_t, LacpPortInfo> port_lacp_info_; // Stores LACP state per physical port
};

} // namespace netflow

#endif // NETFLOW_LACP_MANAGER_HPP
