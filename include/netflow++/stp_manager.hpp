#ifndef NETFLOW_STP_MANAGER_HPP
#define NETFLOW_STP_MANAGER_HPP

#include "packet.hpp" // For Packet class (BPDU is a type of packet)
#include <cstdint>
#include <vector>
#include <map>
#include <optional> // For get_port_state potentially returning optional or a default

namespace netflow {

// Forward declaration for BPDU structure if it were detailed
// struct BpduData;

class StpManager {
public:
    enum class PortState {
        UNKNOWN,  // Default state, or if port is not managed by STP
        DISABLED, // Port is administratively down or STP disabled it
        BLOCKING, // Port does not forward traffic, but receives BPDUs
        LISTENING, // Transitional state: not forwarding, not learning MACs, processing BPDUs
        LEARNING,  // Transitional state: not forwarding, but learning MACs, processing BPDUs
        FORWARDING // Port forwards traffic and processes BPDUs
    };

    struct BridgeConfig {
        uint64_t bridge_id = 0xFFFFFFFFFFFFFFFF; // Lower is better. Typically MAC + priority.
        uint32_t hello_time_seconds = 2;       // Time between sending BPDUs
        uint32_t forward_delay_seconds = 15;   // Delay for Listening and Learning states
        uint32_t max_age_seconds = 20;         // Max age of received BPDU info before discarding

        // Default constructor is fine
        BridgeConfig() = default;

        BridgeConfig(uint64_t id, uint32_t hello = 2, uint32_t fwd_delay = 15, uint32_t age = 20)
            : bridge_id(id), hello_time_seconds(hello), forward_delay_seconds(fwd_delay), max_age_seconds(age) {}
    };

    StpManager() : bridge_config_() {
        // Default bridge config will be used unless set_bridge_config is called.
    }

    explicit StpManager(const BridgeConfig& initial_config) : bridge_config_(initial_config) {}

    void set_bridge_config(const BridgeConfig& config) {
        bridge_config_ = config;
        // TODO: STP logic might need to be re-evaluated if bridge ID or timers change.
        // For example, might need to trigger a new root bridge election process.
    }

    const BridgeConfig& get_bridge_config() const {
        return bridge_config_;
    }

    void set_port_state(uint32_t port_id, PortState state) {
        port_states_[port_id] = state;
        // TODO: Add logging or event generation for state changes.
    }

    PortState get_port_state(uint32_t port_id) const {
        auto it = port_states_.find(port_id);
        if (it != port_states_.end()) {
            return it->second;
        }
        // Default state for unconfigured/unknown ports.
        // Could be DISABLED or BLOCKING depending on desired default behavior.
        return PortState::UNKNOWN;
    }

    // Determines if a port should forward user traffic based on its STP state.
    bool should_forward(uint32_t port_id) const {
        return get_port_state(port_id) == PortState::FORWARDING;
    }

    // Determines if a port should learn MAC addresses.
    bool should_learn(uint32_t port_id) const {
        PortState state = get_port_state(port_id);
        return state == PortState::LEARNING || state == PortState::FORWARDING;
    }

    // Placeholder for processing an incoming BPDU (Bridge Protocol Data Unit).
    // The actual STP logic (Root Bridge election, Port Role calculation, State transitions) is complex.
    void process_bpdu(const Packet& bpdu_packet, uint32_t ingress_port_id) {
        // 1. Decode BPDU from bpdu_packet.data()
        //    - Check if it's a Configuration BPDU or TCN BPDU.
        //    - Extract fields: Root ID, Root Path Cost, Sender Bridge ID, Port ID, Message Age, Max Age, Hello Time, Forward Delay.
        //
        // 2. Update port's BPDU information based on the received BPDU and current port/bridge state.
        //
        // 3. Run STP state machine for the port:
        //    - Compare received BPDU with port's current information.
        //    - Potentially update Root Bridge, Root Port, Designated Ports.
        //    - Transition port states (e.g., from BLOCKING to LISTENING if it becomes a Root Port or Designated Port).
        //
        // Example pseudo-logic:
        // if (get_port_state(ingress_port_id) == PortState::DISABLED) return;
        // ParsedBpduInfo received_bpdu = parse_bpdu(bpdu_packet);
        // PortInfo& port_info = get_port_stp_info(ingress_port_id);
        //
        // if (is_superior_bpdu(received_bpdu, port_info.best_bpdu_received)) {
        //    port_info.best_bpdu_received = received_bpdu;
        //    port_info.message_age_timer.reset(); // Reset message age timer for this BPDU
        //    recalculate_stp(); // This would involve the full STP algorithm
        // }
        //
        // This is a highly simplified placeholder. Real STP is event-driven and timer-based.
    }

    // Placeholder for generating BPDUs to be sent out on designated ports.
    // BPDUs are typically generated based on the bridge's current understanding of the STP topology
    // (e.g., its own Bridge ID, Root ID, Root Path Cost).
    std::vector<Packet> generate_bpdus() {
        std::vector<Packet> bpdus_to_send;
        // For each port:
        // if (is_designated_port(port_id) && get_port_state(port_id) != PortState::DISABLED && get_port_state(port_id) != PortState::BLOCKING) {
        //    // And if hello_timer for this port has expired
        //
        //    // 1. Construct BPDU payload:
        //    //    Set Root ID (current known root or self if root)
        //    //    Set Root Path Cost (cost to reach root or 0 if root)
        //    //    Set Sender Bridge ID (our bridge_config_.bridge_id)
        //    //    Set Port ID (our port_id, possibly with priority)
        //    //    Set Message Age (0 for BPDUs originated by Root Bridge, incremented otherwise)
        //    //    Set Max Age, Hello Time, Forward Delay from bridge_config_ or root's BPDU.
        //
        //    // 2. Create a PacketBuffer for the BPDU.
        //    PacketBuffer* pb = buffer_pool_->allocate_buffer(BPDU_SIZE); // Assuming a buffer pool is accessible
        //    if(pb) {
        //        // Fill pb->data with BPDU payload
        //        // Construct Ethernet header (typically to multicast 01:80:C2:00:00:00)
        //        Packet bpdu_pkt(pb);
        //        // Set MAC addresses, ethertype for BPDU (e.g. LLC encapsulation)
        //        bpdus_to_send.push_back(bpdu_pkt); // This Packet constructor would need to handle ref counting
        //                                         // Or return vector of PacketBuffer* to be wrapped by caller
        //    }
        // }
        return bpdus_to_send; // Placeholder, returns empty vector
    }

    // Call this periodically based on timers (e.g., every second)
    void run_stp_timers_and_logic() {
        // For each port:
        // - Decrement message_age_timer if it has received a BPDU. If it expires, age out the BPDU info.
        // - Decrement forward_delay_timer if in LISTENING or LEARNING state. Transition state if expired.
        // - Check hello_timer for designated ports to generate BPDUs.
        //
        // If any BPDU info aged out or state changed, might need to recalculate_stp().
        // This is where the core STP decision logic would be invoked.
    }


private:
    BridgeConfig bridge_config_;
    std::map<uint32_t, PortState> port_states_;
    // More STP related per-port information would be needed for actual implementation:
    // e.g. std::map<uint32_t, PortStpInfo> port_stp_details_;
    // where PortStpInfo contains:
    //  - Role (Root, Designated, Alternate, Backup, Disabled)
    //  - Received BPDU info (Root ID, Cost, Sender BID, etc.)
    //  - Timers (message age, forward delay)

    // Access to a buffer pool would be needed for generate_bpdus
    // BufferPool* buffer_pool_ = nullptr;
    // public:
    //  void set_buffer_pool(BufferPool* pool) { buffer_pool_ = pool; }

public: // Helper for logging
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
};

} // namespace netflow

#endif // NETFLOW_STP_MANAGER_HPP
