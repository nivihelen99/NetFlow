#ifndef NETFLOW_STP_MANAGER_HPP
#define NETFLOW_STP_MANAGER_HPP

#include "packet.hpp" // For Packet class (BPDU is a type of packet)
#include <cstdint>
#include <vector>
#include <map>
#include <optional> // For get_port_state potentially returning optional or a default
#include "netflow++/logger.hpp"      // For SwitchLogger
#include "netflow++/buffer_pool.hpp" // For BufferPool in generate_bpdus

// Forward declare Packet if it's only used as a const ref in public API here
// class Packet;
// Forward declare BufferPool if it's only used as a ref in public API here // This is now redundant


namespace netflow {

// Definitions from the version of stp_manager.hpp that was consistent with stp_manager.cpp
namespace StpDefaults {
    const uint8_t PROTOCOL_ID = 0x00;
    const uint8_t VERSION_ID_STP = 0x00;
    const uint8_t BPDU_TYPE_CONFIG = 0x00;
    const uint8_t BPDU_TYPE_TCN = 0x80;
    // STP Multicast MAC: 01:80:C2:00:00:00
    const uint8_t STP_MULTICAST_MAC_BYTES[] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x00};
}

struct ReceivedBpduInfo {
    uint64_t root_id = 0xFFFFFFFFFFFFFFFFULL;
    uint32_t root_path_cost = 0xFFFFFFFF;
    uint64_t sender_bridge_id = 0xFFFFFFFFFFFFFFFFULL;
    uint16_t sender_port_id = 0xFFFF; // STP Port ID (Prio+Num)
    uint16_t message_age = 0;    // In 1/256th of a second
    uint16_t max_age = 20 * 256;        // Default 20s
    uint16_t hello_time = 2 * 256;     // Default 2s
    uint16_t forward_delay = 15 * 256;  // Default 15s
    bool tc_flag = false;
    bool tca_flag = false;

    ReceivedBpduInfo() = default;

    bool is_superior_to(const ReceivedBpduInfo& other, uint64_t self_bridge_id) const;
};

// Forward declare ConfigBpdu for StpPortInfo and BridgeConfig
struct ConfigBpdu;


class StpManager {
public:
    enum class PortRole {
        UNKNOWN, ROOT, DESIGNATED, ALTERNATE, BACKUP, DISABLED
    };

    enum class PortState {
        UNKNOWN, DISABLED, BLOCKING, LISTENING, LEARNING, FORWARDING
    };

    struct StpPortInfo {
        uint32_t port_id_internal;
        uint16_t stp_port_id_field; // STP Port ID (Prio + PortNum)
        PortRole role = PortRole::DISABLED;
        PortState state = PortState::DISABLED;
        uint32_t path_cost_to_segment = 19;

        uint64_t designated_bridge_id_for_segment = 0;
        uint16_t designated_port_id_for_segment = 0;
        uint32_t path_cost_from_designated_bridge_to_root = 0xFFFFFFFF;

        uint16_t message_age_timer_seconds = 0;
        uint16_t forward_delay_timer_seconds = 0;
        uint16_t hello_timer_seconds = 0;

        ReceivedBpduInfo received_bpdu;
        bool new_bpdu_received_flag = false;
        uint8_t port_priority = 128;

        StpPortInfo(uint32_t id = 0);
        void update_stp_port_id_field();
        bool has_valid_bpdu_info(uint16_t max_age_limit_seconds) const;
        uint32_t get_total_path_cost_to_root_via_port() const;
    };

    struct BridgeConfig {
        uint64_t bridge_mac_address = 0x000000000000ULL;
        uint16_t bridge_priority = 0x8000;
        uint64_t bridge_id_value;

        uint32_t hello_time_seconds = 2;
        uint32_t forward_delay_seconds = 15;
        uint32_t max_age_seconds = 20;

        ReceivedBpduInfo our_bpdu_info;
        std::optional<uint32_t> root_port_internal_id;

        BridgeConfig(uint64_t mac = 0x000000000001ULL, uint16_t priority = 0x8000,
                     uint32_t hello = 2, uint32_t fwd_delay = 15, uint32_t age = 20);
        void update_bridge_id_value();
        bool is_root_bridge() const;
    };

    StpManager(uint32_t num_ports, uint64_t switch_mac_address, uint16_t switch_priority);

    void set_bridge_mac_address_and_reinit(uint64_t mac);
    void set_bridge_priority_and_reinit(uint16_t priority);
    const BridgeConfig& get_bridge_config() const;
    void admin_set_port_state(uint32_t port_id, bool enable); // To enable/disable port for STP
    PortState get_port_stp_state(uint32_t port_id) const;
    PortRole get_port_stp_role(uint32_t port_id) const;

    void set_port_path_cost(uint32_t port_id, uint32_t cost);
    void set_port_priority(uint32_t port_id, uint8_t priority);

    bool should_forward(uint32_t port_id) const;
    bool should_learn(uint32_t port_id) const;

    void process_bpdu(const Packet& bpdu_packet, uint32_t ingress_port_id, SwitchLogger& logger);
    std::vector<Packet> generate_bpdus(BufferPool& buffer_pool, SwitchLogger& logger);
    void run_stp_timers();

public: // Helpers for logging - keep public
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
    std::string port_role_to_string(PortRole role) const;
    std::map<uint32_t, std::pair<std::string, std::string>> get_all_ports_stp_info_summary() const;

private:
    void initialize_ports(uint32_t num_ports);
    void recalculate_stp_roles_and_states(SwitchLogger& logger); // Added logger param

    BridgeConfig bridge_config_;
    std::map<uint32_t, StpPortInfo> port_stp_info_;
};


// Definition for ConfigBpdu struct (moved from being nested or assumed)
// This should be consistent with the version used in stp_manager.cpp
struct ConfigBpdu {
    uint8_t protocol_id;
    uint8_t version_id;
    uint8_t bpdu_type;
    uint8_t flags;
    uint64_t root_id;
    uint32_t root_path_cost;
    uint64_t bridge_id;
    uint16_t port_id;
    uint16_t message_age;
    uint16_t max_age;
    uint16_t hello_time;
    uint16_t forward_delay;

    ConfigBpdu(); // Default constructor
    void from_bpdu_info_for_sending(const ReceivedBpduInfo& source_info, uint64_t my_bridge_id, uint16_t my_port_id,
                                    uint16_t effective_message_age, uint16_t root_max_age,
                                    uint16_t root_hello_time, uint16_t root_forward_delay);
    ReceivedBpduInfo to_received_bpdu_info() const;

    static uint64_t htonll(uint64_t val);
    static uint64_t ntohll(uint64_t val);
};
const size_t CONFIG_BPDU_PAYLOAD_SIZE = 34;


} // namespace netflow

#endif // NETFLOW_STP_MANAGER_HPP
