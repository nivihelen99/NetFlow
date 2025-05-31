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
#include "netflow++/logger.hpp" // For SwitchLogger, if used in future methods
#include "netflow++/buffer_pool.hpp" // For BufferPool, used in generate_lacpdus

// Forward declare PacketClassifier if its FlowKey might be used directly for hashing inspiration
// namespace netflow { class PacketClassifier; }

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
    uint16_t lacp_rate = 1;
    uint16_t actor_admin_key = 0;

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
    uint16_t port_priority_val = 128;

    LacpPortInfo(uint32_t phys_id = 0);
    void set_actor_state_flag(LacpStateFlag flag, bool set);
    bool get_actor_state_flag(LacpStateFlag flag) const;
};


class LacpManager {
public:
    // Constructor needs switch's base MAC and system priority for LACP System ID
    LacpManager(uint64_t switch_base_mac, uint16_t system_priority = 32768);

    // Creates a new Link Aggregation Group (LAG).
    bool create_lag(LagConfig& config) { // Pass by non-const ref to update its key if needed
        if (config.lag_id == 0) {
            return false;
        }
        if (lags_.count(config.lag_id)) {
            // std::cerr << "Error: LAG ID " << config.lag_id << " already exists." << std::endl;
            return false;
        }

        // Check if any proposed member ports are already in other LAGs
        for (uint32_t port_id : config.member_ports) {
            if (port_to_lag_map_.count(port_id)) {
                // std::cerr << "Error: Port " << port_id << " is already part of LAG "
                //           << port_to_lag_map_[port_id] << "." << std::endl;
                return false; // Strict: port cannot be in multiple LAGs initially
            }
        }

        lags_[config.lag_id] = config;
        // Sort and unique member_ports in the stored config
        std::sort(lags_[config.lag_id].member_ports.begin(), lags_[config.lag_id].member_ports.end());
        lags_[config.lag_id].member_ports.erase(
            std::unique(lags_[config.lag_id].member_ports.begin(), lags_[config.lag_id].member_ports.end()),
            lags_[config.lag_id].member_ports.end()
        );

        for (uint32_t port_id : lags_[config.lag_id].member_ports) {
            port_to_lag_map_[port_id] = config.lag_id;
        }
        // std::cout << "LAG " << config.lag_id << " created." << std::endl;
        return true;
    }

    // Adds a physical port to an existing LAG.
    // Returns true if successful.
    bool add_port_to_lag(uint32_t lag_id, uint32_t port_id) {
        auto lag_it = lags_.find(lag_id);
        if (lag_it == lags_.end()) {
            // std::cerr << "Error: LAG " << lag_id << " does not exist." << std::endl;
            return false;
        }

        auto port_map_it = port_to_lag_map_.find(port_id);
        if (port_map_it != port_to_lag_map_.end()) {
            if (port_map_it->second == lag_id) {
                return true; // Port already in this LAG
            } else {
                // std::cerr << "Error: Port " << port_id << " is already part of a different LAG ("
                //           << port_map_it->second << ")." << std::endl;
                return false; // Port already in a different LAG
            }
        }

        lag_it->second.member_ports.push_back(port_id);
        // Ensure no duplicates and maintain sorted order
        std::sort(lag_it->second.member_ports.begin(), lag_it->second.member_ports.end());
        lag_it->second.member_ports.erase(
            std::unique(lag_it->second.member_ports.begin(), lag_it->second.member_ports.end()),
            lag_it->second.member_ports.end()
        );
        port_to_lag_map_[port_id] = lag_id;
        // std::cout << "Port " << port_id << " added to LAG " << lag_id << "." << std::endl;
        return true;
    }

    // Removes a physical port from a LAG.
    // Returns true if successful.
    bool remove_port_from_lag(uint32_t lag_id, uint32_t port_id) {
        auto lag_it = lags_.find(lag_id);
        if (lag_it == lags_.end()) {
            // std::cerr << "Warning: LAG " << lag_id << " not found for port removal." << std::endl;
            return false;
        }

        auto port_map_it = port_to_lag_map_.find(port_id);
        if (port_map_it == port_to_lag_map_.end() || port_map_it->second != lag_id) {
            // std::cerr << "Warning: Port " << port_id << " is not part of LAG " << lag_id << "." << std::endl;
            return false; // Port not in this LAG
        }

        auto& members = lag_it->second.member_ports;
        members.erase(std::remove(members.begin(), members.end(), port_id), members.end());
        port_to_lag_map_.erase(port_id);

        // std::cout << "Port " << port_id << " removed from LAG " << lag_id << "." << std::endl;
        if (members.empty()) {
            // Optionally remove LAG if no members left, or leave it configured but inactive.
            // For now, let's leave it, user can explicitly delete_lag.
            // std::cout << "Warning: LAG " << lag_id << " has no more members." << std::endl;
        }
        return true;
    }

    // Deletes an entire LAG.
    void delete_lag(uint32_t lag_id) {
        auto lag_it = lags_.find(lag_id);
        if (lag_it != lags_.end()) {
            for (uint32_t port_id : lag_it->second.member_ports) {
                port_to_lag_map_.erase(port_id);
            }
            lags_.erase(lag_id);
            // std::cout << "LAG " << lag_id << " deleted." << std::endl;
        }
    }

    // Placeholder: Selects an egress port from a LAG based on packet hash.
    // Actual hashing and selection is more complex and depends on active/selected members.
    // Returns a physical port_id.
    uint32_t select_egress_port(uint32_t lag_id, const Packet& pkt) const {
        auto it = lags_.find(lag_id);
        if (it == lags_.end() || it->second.member_ports.empty()) {
            // std::cerr << "Error: Invalid LAG ID " << lag_id << " or no member ports for selection." << std::endl;
            return 0; // 0 could signify an invalid port or "drop". Needs clear definition.
                      // Or throw an exception for critical error.
        }

        const LagConfig& lag_config = it->second;
        const std::vector<uint32_t>& members = lag_config.member_ports;

        // TODO: Implement actual hashing based on lag_config.hash_mode and packet (pkt)
        // For now, simple round-robin or first port.
        // Example using a very simple hash of some packet fields:
        // PacketClassifier::FlowKey flow_key = some_classifier_instance.extract_flow_key(pkt);
        // uint32_t hash = some_classifier_instance.hash_flow(flow_key);
        // uint32_t member_index = hash % members.size();
        // return members[member_index];

        // Using a mutable index for simple round-robin (if LacpManager is not const for this method)
        // Or, if it must be const, then hash is better.
        // For this placeholder with const method:
        if (!members.empty()) {
             // Simplistic: hash source MAC to choose port (very basic)
            uint32_t hash_val = 0;
            if(pkt.src_mac().has_value()){
                for(int i=0; i<6; ++i) hash_val += pkt.src_mac().value().bytes[i];
            }
            return members[hash_val % members.size()];
        }

        return members[0]; // Fallback to first available port if all else fails
    }

    // Placeholder: Actual LACPDU processing is complex (state machines, timers, etc.)
    void process_lacpdu(const Packet& lacpdu_packet, uint32_t ingress_port_id) {
        // 1. Decode LACPDU from lacpdu_packet.
        // 2. Check if ingress_port_id is part of a LAG configured for LACP (active or passive).
        // 3. Update actor/partner information for the port based on received LACPDU.
        // 4. Run LACP state machines (Receive, Mux, Periodic, Churn Detection etc.).
        //    This involves:
        //    - Actor state updates (e.g., LACP_Activity, LACP_Timeout, Aggregation, Sync, Collecting, Distributing).
        //    - Partner state updates.
        //    - Port selection logic to determine which ports can be aggregated based on compatible actor/partner info.
        //    - Attaching/detaching ports from the aggregator.
        // std::cout << "Placeholder: Received LACPDU on port " << ingress_port_id
        //           << ". (Size: " << lacpdu_packet.get_buffer()->size << ")" << std::endl;
    }

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

    // Methods that were defined in .cpp but not declared in .hpp
    std::vector<Packet> generate_lacpdus(BufferPool& buffer_pool);
    void run_lacp_timers_and_statemachines();
    void initialize_lacp_port_info(uint32_t port_id, const LagConfig& lag_config);
    void run_lacp_rx_machine(uint32_t port_id);
    void run_lacp_periodic_tx_machine(uint32_t port_id);
    void run_lacp_mux_machine(uint32_t port_id);
    void update_port_selection_logic(uint32_t port_id);

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
