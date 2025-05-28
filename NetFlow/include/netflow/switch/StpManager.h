#ifndef NETFLOW_SWITCH_STPMANAGER_H
#define NETFLOW_SWITCH_STPMANAGER_H

#include "netflow/packet/Packet.h" // For Packet, if BPDUs are parsed/generated as Packet objects
#include <cstdint>
#include <array>  // For std::array
#include <vector>
#include <unordered_map>
#include <mutex>
#include <chrono> // For timers (hello timer, forward delay, max age)

// Define MACAddress type
using MACAddress = std::array<uint8_t, 6>;

// Define Bridge and Port Identifiers (simplified)
using BridgeId = uint64_t; // Typically 8 bytes: 2B priority + 6B MAC address
using PortId = uint16_t;   // Interface identifier

// STP Port States
enum class StpPortState {
    DISABLED,   // Port is administratively down or not participating in STP
    BLOCKING,   // Port is not forwarding frames, listening for BPDUs
    LISTENING,  // Transitional state after blocking, processing BPDUs, not forwarding/learning
    LEARNING,   // Transitional state after listening, populating MAC table, not forwarding
    FORWARDING, // Port is fully operational, forwarding frames and learning MACs
    BROKEN      // Port has encountered an error
};

// Simplified BPDU structure (Configuration BPDU)
// Real BPDUs are more complex (LLC encapsulation, specific fields for different STP versions)
struct SimpleBpdu {
    uint16_t protocol_id;    // 0x0000 for STP
    uint8_t version_id;      // 0x00 for STP, 0x02 for RSTP, 0x03 for MSTP
    uint8_t bpdu_type;       // 0x00 for Configuration BPDU, 0x80 for TCN BPDU
    uint8_t flags;           // Topology Change, Proposal, Port Role, Learning, Forwarding, Agreement, TC Ack
    BridgeId root_bridge_id;
    uint32_t root_path_cost;
    BridgeId designated_bridge_id; // Bridge sending this BPDU
    PortId designated_port_id;   // Port on the designated bridge sending this BPDU
    uint16_t message_age;    // In 1/256th of a second
    uint16_t max_age;        // In 1/256th of a second
    uint16_t hello_time;     // In 1/256th of a second
    uint16_t forward_delay;  // In 1/256th of a second
    // RSTP/MSTP have more fields
};

struct BridgeConfig {
    BridgeId bridge_id;
    uint32_t bridge_priority; // Part of bridge_id, but often configured separately
    MACAddress bridge_mac;    // Part of bridge_id

    // STP timers (host byte order, in seconds for simplicity here, converted for BPDU)
    uint16_t hello_time_sec = 2;
    uint16_t max_age_sec = 20;
    uint16_t forward_delay_sec = 15;

    bool stp_enabled = true;
};

struct PortStpInfo {
    StpPortState state = StpPortState::BLOCKING;
    PortId port_id; // Our port ID for this physical interface
    uint32_t path_cost = 19; // Default for 100Mbps, adjust based on speed
    
    // Information from the best BPDU received on this port
    BridgeId designated_root_bridge_id;
    uint32_t designated_root_path_cost = 0;
    BridgeId designated_bridge_id;
    PortId designated_port_id_on_designated_bridge; // Port ID *of the sender* of the BPDU

    std::chrono::steady_clock::time_point last_bpdu_received_time;
    bool is_root_port = false;
    bool is_designated_port = true; // Assume designated unless a better BPDU comes or it's root

    // Timers for port state transitions
    std::chrono::steady_clock::time_point state_timer_expires;


    PortStpInfo(PortId pid = 0) : port_id(pid) {
        designated_root_bridge_id = 0; // Initialize to invalid/max value
        designated_bridge_id = 0;
        designated_port_id_on_designated_bridge = 0;
    }
};


class StpManager {
public:
    explicit StpManager();

    void set_bridge_config(const BridgeConfig& config);
    const BridgeConfig& get_bridge_config() const;

    // Port configuration
    bool configure_port(PortId port_id, uint32_t path_cost, bool stp_enabled = true);
    bool set_port_state(PortId port_id, StpPortState new_state);
    StpPortState get_port_state(PortId port_id) const;
    const PortStpInfo* get_port_stp_info(PortId port_id) const;


    // Decision: Should a data frame be forwarded on this port based on STP state?
    bool should_forward(PortId port_id) const;

    // BPDU Processing
    // `bpdu_data` is raw BPDU payload (after LLC)
    // `len` is length of bpdu_data
    // `ingress_port` is the port on which this BPDU was received
    void process_bpdu(const unsigned char* bpdu_data, size_t len, PortId ingress_port);

    // BPDU Generation (conceptual)
    // Returns a vector of bytes representing the BPDU to be sent.
    // This would be called periodically for designated ports.
    std::vector<unsigned char> generate_bpdu(PortId port_id);

    // Main STP logic execution tick (call periodically, e.g., every second)
    // This would handle timers, state transitions, root/designated port elections.
    void run_stp_iteration();

private:
    BridgeConfig bridge_config_;
    // Root bridge information as believed by this bridge
    BridgeId current_root_bridge_id_;
    uint32_t current_root_path_cost_;
    PortId root_port_id_; // Our port that leads to the root bridge (0 if we are root)

    std::unordered_map<PortId, PortStpInfo> port_stp_info_;
    mutable std::mutex stp_mutex_;

    std::chrono::steady_clock::time_point last_bpdu_sent_time_; // For regulating BPDU generation

    // STP logic helper methods
    void update_port_role(PortId port_id);
    void elect_root_port(); // Determines which port is the root port
    void determine_designated_ports(); // Determines which ports are designated
    void transition_port_state(PortId port_id, StpPortState target_state);
    bool is_superior_bpdu(const SimpleBpdu& current_bpdu, const SimpleBpdu& new_bpdu, PortId rcv_port) const;
    SimpleBpdu create_bpdu_from_port_info(PortId port_id) const;

public: // Making these public for broader utility, e.g. serialize_simple_bpdu
    // Helper to convert seconds to 1/256th for BPDU fields
    static uint16_t seconds_to_bpdu_time(uint16_t seconds) { return htons(seconds * 256); }
    static uint16_t bpdu_time_to_seconds(uint16_t bpdu_time) { return ntohs(bpdu_time) / 256; }
};

#endif // NETFLOW_SWITCH_STPMANAGER_H


