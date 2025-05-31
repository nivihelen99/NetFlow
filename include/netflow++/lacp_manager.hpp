#ifndef NETFLOW_LACP_MANAGER_HPP
#define NETFLOW_LACP_MANAGER_HPP

#include <cstdint>
#include <vector>
#include <map>
#include <optional>
#include <functional>
#include <algorithm> // For std::sort, std::unique, std::remove
#include <string>    // Potentially for names or logging
#include <iostream>  // For placeholder logging

#include "packet.hpp" // For Packet class, used in select_egress_port and process_lacpdu
#include "netflow++/logger.hpp" // For SwitchLogger
#include "netflow++/buffer_pool.hpp" // For BufferPool, used in generate_lacpdus

// Forward declare PacketClassifier if its FlowKey might be used directly for hashing inspiration
// namespace netflow { class PacketClassifier; }
namespace netflow {
    class SwitchLogger; // Forward declare SwitchLogger
}

namespace netflow {

// LACP Constants (already present from previous merge, ensure they are kept if this block is fully replaced)
namespace LacpDefaults {
    const uint8_t LACP_SUBTYPE = 0x01;
    const uint8_t LACP_VERSION = 0x01;
    const uint64_t LACP_MULTICAST_MAC = 0x0180C2000002ULL;
    const uint16_t LACP_ETHERTYPE = 0x8809;
}

// LacpStateFlag enum (already present from previous merge)
enum LacpStateFlag : uint8_t {
    LACP_ACTIVITY     = 0x01,
    LACP_TIMEOUT      = 0x02,
    AGGREGATION       = 0x04,
    SYNCHRONIZATION   = 0x08,
    COLLECTING        = 0x10,
    DISTRIBUTING      = 0x20,
    DEFAULTED         = 0x40,
    EXPIRED           = 0x80
};

// Lacpdu struct (already present from previous merge)
struct Lacpdu {
    uint8_t subtype;
    uint8_t version_number;
    uint8_t tlv_type_actor;
    uint8_t actor_info_length;
    uint16_t actor_system_priority;
    uint8_t actor_system_mac[6];
    uint16_t actor_key;
    uint16_t actor_port_priority;
    uint16_t actor_port_number;
    uint8_t actor_state;
    uint8_t reserved_actor[3];
    uint8_t tlv_type_partner;
    uint8_t partner_info_length;
    uint16_t partner_system_priority;
    uint8_t partner_system_mac[6];
    uint16_t partner_key;
    uint16_t partner_port_priority;
    uint16_t partner_port_number;
    uint8_t partner_state;
    uint8_t reserved_partner[3];
    uint8_t tlv_type_collector;
    uint8_t collector_info_length;
    uint16_t collector_max_delay;
    uint8_t reserved_collector[12];
    uint8_t tlv_type_terminator;
    uint8_t terminator_length;
    uint8_t reserved_terminator[50];

    Lacpdu(); // Assumes default constructor definition exists or will be added
    uint64_t get_actor_system_id() const;
    void set_actor_system_id(uint64_t system_id);
};
const size_t LACPDU_MIN_SIZE = 60;


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
    uint32_t lag_id = 0; // Unique identifier for the Link Aggregation Group
    std::vector<uint32_t> member_ports; // List of physical port IDs in this LAG
    LacpHashMode hash_mode = LacpHashMode::SRC_DST_IP_L4_PORT; // Hashing mode for load balancing
    bool active_mode = true;
    uint16_t lacp_rate = 1; // 1 for fast (short timeout), 0 for slow (long timeout)
    uint16_t actor_admin_key = 0;

    // New member for dynamic list of active ports
    std::vector<uint32_t> active_distributing_members; // Ports in this LAG currently in COLLECTING_DISTRIBUTING state

    LagConfig() = default;
};

// LacpPortInfo struct (already present from previous merge)
struct LacpPortInfo {
    uint32_t port_id_physical;
    uint64_t actor_system_id_val = 0;
    uint16_t actor_port_id_val = 0;
    uint16_t actor_key_val = 0;
    uint8_t actor_state_val = 0;
    uint64_t partner_system_id_val = 0;
    uint16_t partner_port_id_val = 0;
    uint16_t partner_key_val = 0;
    uint8_t partner_state_val = 0;
    bool is_active_member_of_lag = false;
    uint32_t current_aggregator_id = 0;
    uint16_t current_while_timer_ticks = 0;
    uint16_t short_timeout_timer_ticks = 0;
    uint16_t long_timeout_timer_ticks = 0;
    enum class MuxMachineState { DETACHED, WAITING, ATTACHED, COLLECTING_DISTRIBUTING };
    MuxMachineState mux_state = MuxMachineState::DETACHED;
    enum class RxMachineState { INITIALIZE, PORT_DISABLED, LACP_DISABLED, EXPIRED, DEFAULTED, CURRENT };
    RxMachineState rx_state = RxMachineState::INITIALIZE;
    enum class PeriodicTxState { NO_PERIODIC, FAST_PERIODIC, SLOW_PERIODIC, PERIODIC_TX };
    PeriodicTxState periodic_tx_state = PeriodicTxState::NO_PERIODIC;
    uint16_t port_priority_val = 128; // Default LACP port priority (IEEE 802.1AX Table 6-1)

    // Event flags for state machines
    bool pdu_received_event = false; // Set by process_lacpdu, consumed by RxMachine
    bool current_while_timer_expired_event = false; // Set by timer logic (current_while_timer), consumed by RxMachine
    bool short_timeout_timer_expired_event = false; // Set by timer logic (short_timeout_timer), consumed by PeriodicTxMachine
    bool long_timeout_timer_expired_event = false;  // Set by timer logic (long_timeout_timer), consumed by PeriodicTxMachine
    bool ntt_event = false; // Set by RxMachine or PeriodicTxMachine, consumed by generate_lacpdus & PeriodicTxMachine
    bool wait_while_timer_expired_event = false; // Set by timer logic (aggregate_wait_timer), consumed by MuxMachine

    // Mux Machine specific
    uint16_t current_wait_while_timer_ticks = 0; // For Mux machine's WAITING state
    bool selected_for_aggregation = false; // Set by Selection Logic, consumed by MuxMachine


    // Assumed external conditions (can be managed by InterfaceManager or set directly for testing)
    bool port_enabled = false; // Physical port operational status
    bool lacp_enabled = false; // LACP protocol enabled on this port

    // Temporary storage for the actor information from the last received PDU
    // This is used by the RxMachine to compare and record partner info.
    struct PduActorInfo {
        uint64_t system_id = 0;
        uint16_t key = 0;
        uint16_t port_priority = 0;
        uint16_t port_number = 0;
        uint8_t state = 0;
        bool valid = false; // Indicates if this struct holds valid data from a new PDU
    } last_received_pdu_actor_info;


    LacpPortInfo(uint32_t phys_id = 0);
    void set_actor_state_flag(LacpStateFlag flag, bool set);
    bool get_actor_state_flag(LacpStateFlag flag) const;
    void set_partner_state_flag(LacpStateFlag flag, bool set); // Added
    bool get_partner_state_flag(LacpStateFlag flag) const;   // Added
};

// Timer constants (in terms of 1-second ticks for run_lacp_timers_and_statemachines)
const uint16_t SHORT_TIMEOUT_TICKS = 3; // 3 seconds
const uint16_t LONG_TIMEOUT_TICKS = 90; // 90 seconds
const uint16_t AGGREGATE_WAIT_TIME_TICKS = 2; // 2 seconds, IEEE 802.1AX default for Aggregate Wait Time


class LacpManager {
public:
    // Constructor needs switch's base MAC and system priority for LACP System ID
    LacpManager(uint64_t switch_base_mac, uint16_t system_priority = 32768);

    // Creates a new Link Aggregation Group (LAG).
    // Definition moved to .cpp file
    bool create_lag(LagConfig& config);

    // Adds a physical port to an existing LAG.
    // Returns true if successful.
    // Definition moved to .cpp file
    bool add_port_to_lag(uint32_t lag_id, uint32_t port_id);

    // Removes a physical port from a LAG.
    // Returns true if successful.
    // Definition moved to .cpp file
    bool remove_port_from_lag(uint32_t lag_id, uint32_t port_id);

    // Deletes an entire LAG.
    // Definition moved to .cpp file
    void delete_lag(uint32_t lag_id);

    // Selects an egress port from a LAG based on packet hash.
    // Returns a physical port_id.
    // Definition moved to .cpp file
    uint32_t select_egress_port(uint32_t lag_id, const Packet& pkt) const;

    // Processes an incoming LACPDU.
    // Definition moved to .cpp file
    void process_lacpdu(const Packet& lacpdu_packet, uint32_t ingress_port_id);

    // Checks if a physical port is part of any LAG.
    bool is_port_in_lag(uint32_t port_id) const { // Can remain inline
        return port_to_lag_map_.count(port_id);
    }

    // Gets the LAG ID for a given physical port, if it's part of one.
    std::optional<uint32_t> get_lag_for_port(uint32_t port_id) const { // Can remain inline
        auto it = port_to_lag_map_.find(port_id);
        if (it != port_to_lag_map_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    // Retrieves the configuration for a specific LAG.
    std::optional<LagConfig> get_lag_config(uint32_t lag_id) const { // Can remain inline
        auto it = lags_.find(lag_id);
        if (it != lags_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    // Retrieves all configured LAGs
    const std::map<uint32_t, LagConfig>& get_all_lags() const { // Can remain inline
        return lags_;
    }

    // Generates LACPDUs for transmission.
    std::vector<Packet> generate_lacpdus(BufferPool& buffer_pool);
    // Runs LACP timers and state machines for all relevant ports.
    void run_lacp_timers_and_statemachines();
    // Initializes LACP parameters for a port when it's added to a LAG or LACP is enabled.
    void initialize_lacp_port_info(uint32_t port_id, const LagConfig& lag_config);
    // Runs the LACP Receive state machine for a given port.
    void run_lacp_rx_machine(uint32_t port_id);
    // Helper functions for RxMachine, to be defined in .cpp
    void record_defaulted_partner(LacpPortInfo& port_info);
    void record_pdu_partner_info(LacpPortInfo& port_info); // Uses port_info.last_received_pdu_actor_info
    void update_default_selected_partner_info(LacpPortInfo& port_info, const LagConfig& lag_config); // May need lag_config
    bool compare_pdu_with_partner_info(const LacpPortInfo::PduActorInfo& pdu_actor_info, const LacpPortInfo& port_info);
    void set_current_while_timer(LacpPortInfo& port_info, bool is_short_timeout);
    void update_ntt(LacpPortInfo& port_info);
    bool partner_is_short_timeout(const LacpPortInfo& port_info); // Added for PeriodicTxMachine


    // Runs the LACP Periodic Transmission state machine for a given port.
    void run_lacp_periodic_tx_machine(uint32_t port_id);
    // Runs the LACP Mux state machine for a given port.
    void run_lacp_mux_machine(uint32_t port_id);
    // Helper functions for MuxMachine (some might be simple enough to inline in SM)
    void detach_mux_from_aggregator(uint32_t port_id, LacpPortInfo& port_info);
    void attach_mux_to_aggregator(uint32_t port_id, LacpPortInfo& port_info);
    void disable_collecting_distributing(LacpPortInfo& port_info);
    void enable_collecting_distributing(LacpPortInfo& port_info);
    bool check_port_ready(const LacpPortInfo& port_info);
    void update_port_selection_status(uint32_t port_id, LacpPortInfo& port_info); // Placeholder for Selection Logic
    bool check_aggregator_ready_for_port(const LacpPortInfo& port_info); // Checks if partner is ready for this port to join
    bool check_partner_in_sync(const LacpPortInfo& port_info);
    bool check_partner_in_sync_and_collecting(const LacpPortInfo& port_info);
    void stop_wait_while_timer(LacpPortInfo& port_info);


    // Updates port selection logic (e.g., for an aggregator).
    void update_port_selection_logic(uint32_t port_id); // Or perhaps lag_id

    void set_logger(SwitchLogger* logger);

    // New methods for CLI configuration
    void set_actor_system_priority(uint16_t priority);
    void set_port_lacp_priority(uint32_t port_id, uint16_t priority);
    std::optional<LacpPortInfo> get_port_lacp_info(uint32_t port_id) const;
    bool configure_lag_setting(uint32_t lag_id, std::function<void(LagConfig&)> modifier_fn);

private:
    uint64_t switch_mac_address_; // Base MAC for the switch
    uint16_t lacp_system_priority_; // LACP system priority for the switch
    uint64_t actor_system_id_;      // Combined system_priority + switch_mac_address

    std::map<uint32_t, LagConfig> lags_;
    std::map<uint32_t, uint32_t> port_to_lag_map_;
    std::map<uint32_t, LacpPortInfo> port_lacp_info_; // Stores LACP state per physical port

    SwitchLogger* logger_ = nullptr; // Optional logger
};

} // namespace netflow

#endif // NETFLOW_LACP_MANAGER_HPP
