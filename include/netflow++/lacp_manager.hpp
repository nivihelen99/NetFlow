#ifndef NETFLOW_LACP_MANAGER_HPP
#define NETFLOW_LACP_MANAGER_HPP

#include "packet.hpp"        // For netflow::Packet
#include "netflow++/logger.hpp"      // For netflow::SwitchLogger
#include "netflow++/buffer_pool.hpp" // For netflow::BufferPool

#include <cstdint>    // For uintX_t types
#include <vector>     // For std::vector
#include <map>        // For std::map
#include <optional>   // For std::optional
#include <functional> // For std::function
#include <algorithm>  // For std::sort, std::unique, std::remove (used in .cpp)
#include <string>     // For std::string (logging, names)
#include <iostream>   // For std::cout, std::cerr (placeholder logging)
#include <cstddef>    // For std::size_t


// Forward declare PacketClassifier if its FlowKey might be used directly for hashing inspiration
// namespace netflow { class PacketClassifier; }
// SwitchLogger is included via logger.hpp, so forward declaration is not needed.

namespace netflow {

namespace LacpDefaults {
    const uint8_t LACP_SUBTYPE = 0x01;
    const uint8_t LACP_VERSION = 0x01;
    const uint64_t LACP_MULTICAST_MAC_RAW = 0x0180C2000002ULL; // Raw value
    // const MacAddress LACP_MULTICAST_MAC = MacAddress(std::to_string(LACP_MULTICAST_MAC_RAW)); // If MacAddress can take uint64_t or string
    const uint16_t LACP_ETHERTYPE = 0x8809;
} // namespace LacpDefaults

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

    Lacpdu();
    uint64_t get_actor_system_id() const; // Implementation in .cpp
    void set_actor_system_id(uint64_t system_id); // Implementation in .cpp
};
const std::size_t LACPDU_MIN_SIZE = 60; // Corrected to std::size_t


enum class LacpHashMode {
    SRC_MAC, DST_MAC, SRC_DST_MAC,
    SRC_IP, DST_IP, SRC_DST_IP,
    SRC_PORT, DST_PORT, SRC_DST_PORT,
    SRC_DST_IP_L4_PORT
};

struct LagConfig {
    uint32_t lag_id = 0;
    std::vector<uint32_t> member_ports;
    LacpHashMode hash_mode = LacpHashMode::SRC_DST_IP_L4_PORT;
    bool active_mode = true;
    uint16_t lacp_rate = 1; // 1 for fast (short timeout), 0 for slow
    uint16_t actor_admin_key = 0;
    std::vector<uint32_t> active_distributing_members;

    LagConfig() = default;
};

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
    uint16_t port_priority_val = 128;

    bool pdu_received_event = false;
    bool current_while_timer_expired_event = false;
    bool short_timeout_timer_expired_event = false;
    bool long_timeout_timer_expired_event = false;
    bool ntt_event = false;
    bool wait_while_timer_expired_event = false;
    uint16_t current_wait_while_timer_ticks = 0;
    bool selected_for_aggregation = false;
    bool port_enabled = false;
    bool lacp_enabled = false;

    struct PduActorInfo {
        uint64_t system_id = 0;
        uint16_t key = 0;
        uint16_t port_priority = 0;
        uint16_t port_number = 0;
        uint8_t state = 0;
        bool valid = false;
    } last_received_pdu_actor_info;

    LacpPortInfo(uint32_t phys_id = 0);
    void set_actor_state_flag(LacpStateFlag flag, bool set);
    bool get_actor_state_flag(LacpStateFlag flag) const;
    void set_partner_state_flag(LacpStateFlag flag, bool set);
    bool get_partner_state_flag(LacpStateFlag flag) const;
};

const uint16_t SHORT_TIMEOUT_TICKS = 3;
const uint16_t LONG_TIMEOUT_TICKS = 90;
const uint16_t AGGREGATE_WAIT_TIME_TICKS = 2;

class LacpManager {
public:
    LacpManager(uint64_t switch_base_mac, uint16_t system_priority = 32768);

    bool create_lag(LagConfig& config);
    bool add_port_to_lag(uint32_t lag_id, uint32_t port_id);
    bool remove_port_from_lag(uint32_t lag_id, uint32_t port_id);
    void delete_lag(uint32_t lag_id);
    uint32_t select_egress_port(uint32_t lag_id, const Packet& pkt) const;
    void process_lacpdu(const Packet& lacpdu_packet, uint32_t ingress_port_id);

    bool is_port_in_lag(uint32_t port_id) const;
    std::optional<uint32_t> get_lag_for_port(uint32_t port_id) const;
    std::optional<LagConfig> get_lag_config(uint32_t lag_id) const;
    const std::map<uint32_t, LagConfig>& get_all_lags() const;

    std::vector<Packet> generate_lacpdus(BufferPool& buffer_pool);
    void run_lacp_timers_and_statemachines();
    void initialize_lacp_port_info(uint32_t port_id, const LagConfig& lag_config);
    void run_lacp_rx_machine(uint32_t port_id);
    void record_defaulted_partner(LacpPortInfo& port_info);
    void record_pdu_partner_info(LacpPortInfo& port_info);
    void update_default_selected_partner_info(LacpPortInfo& port_info, const LagConfig& lag_config);
    bool compare_pdu_with_partner_info(const LacpPortInfo::PduActorInfo& pdu_actor_info, const LacpPortInfo& port_info);
    void set_current_while_timer(LacpPortInfo& port_info, bool is_short_timeout);
    void update_ntt(LacpPortInfo& port_info);
    bool partner_is_short_timeout(const LacpPortInfo& port_info);

    void run_lacp_periodic_tx_machine(uint32_t port_id);
    void run_lacp_mux_machine(uint32_t port_id);
    void detach_mux_from_aggregator(uint32_t port_id, LacpPortInfo& port_info);
    void attach_mux_to_aggregator(uint32_t port_id, LacpPortInfo& port_info);
    void disable_collecting_distributing(LacpPortInfo& port_info);
    void enable_collecting_distributing(LacpPortInfo& port_info);
    bool check_port_ready(const LacpPortInfo& port_info);
    void update_port_selection_status(uint32_t port_id, LacpPortInfo& port_info);
    bool check_aggregator_ready_for_port(const LacpPortInfo& port_info);
    bool check_partner_in_sync(const LacpPortInfo& port_info);
    bool check_partner_in_sync_and_collecting(const LacpPortInfo& port_info);
    void stop_wait_while_timer(LacpPortInfo& port_info);

    void update_port_selection_logic(uint32_t port_id);
    void set_logger(SwitchLogger* logger);
    void set_actor_system_priority(uint16_t priority);
    void set_port_lacp_priority(uint32_t port_id, uint16_t priority);
    std::optional<LacpPortInfo> get_port_lacp_info(uint32_t port_id) const;
    bool configure_lag_setting(uint32_t lag_id, std::function<void(LagConfig&)> modifier_fn);

private:
    uint64_t switch_mac_address_;
    uint16_t lacp_system_priority_;
    uint64_t actor_system_id_;

    std::map<uint32_t, LagConfig> lags_;
    std::map<uint32_t, uint32_t> port_to_lag_map_; // Key: physical port_id, Value: lag_id
    std::map<uint32_t, LacpPortInfo> port_lacp_info_;

    SwitchLogger* logger_ = nullptr;
};

} // namespace netflow

#endif // NETFLOW_LACP_MANAGER_HPP
