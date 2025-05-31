#pragma once

#include "netflow++/lldp_defs.hpp" // Defines LldpNeighborInfo, constants, etc.
#include <vector>
#include <map>
#include <string>
#include <chrono>
#include <mutex>
#include <optional> // For potentially optional return types or parameters if needed later

// Forward declarations
namespace netflow {
class Packet; // Assuming Packet class is defined elsewhere
class InterfaceManager; // Assuming InterfaceManager class is defined elsewhere
class Switch; // Forward declaration for Switch
// class ConfigManager; // Forward declare if used for system name/description
}

namespace netflow {

// Configuration for LLDP on a per-port basis
struct LldpPortConfig {
    bool enabled = false;
    uint32_t tx_interval_seconds = 30; // How often to send LLDP frames
    uint32_t ttl_multiplier = 4;      // TTL = tx_interval * ttl_multiplier
    std::chrono::steady_clock::time_point next_tx_time; // When to send next frame

    LldpPortConfig() : next_tx_time(std::chrono::steady_clock::now()) {} // Initialize next_tx_time
};

class LldpManager {
public:
    // Constructor - takes Switch and InterfaceManager.
    explicit LldpManager(Switch& owner_switch, InterfaceManager& if_mgr);
    // explicit LldpManager(Switch& owner_switch, InterfaceManager& if_mgr, ConfigManager& cfg_mgr); // Alternative
    ~LldpManager(); // Default is fine for now

    // Processes an incoming LLDP frame received on a specific port
    void process_lldp_frame(const Packet& packet, uint32_t ingress_port);

    // Manually triggers sending an LLDP frame on a specific port
    void send_lldp_frame(uint32_t port_id);

    // Retrieves LLDP neighbors discovered on a specific port
    std::vector<LldpNeighborInfo> get_neighbors(uint32_t port_id) const;

    // Retrieves all LLDP neighbors discovered, mapped by port ID
    std::map<uint32_t, std::vector<LldpNeighborInfo>> get_all_neighbors() const;

    // Configures LLDP behavior for a specific port
    void configure_port(uint32_t port_id, bool enabled, uint32_t tx_interval = 30, uint32_t ttl_multiplier = 4);

    // Retrieves the current LLDP configuration for a specific port
    LldpPortConfig get_port_config(uint32_t port_id) const;

    // Called periodically (e.g., every second by a global timer)
    // to handle LLDP frame transmission and neighbor expiry.
    void handle_timer_tick();

private:
    Switch& owner_switch_;
    InterfaceManager& interface_manager_;
    // ConfigManager& config_manager_; // If used for system details

    std::map<uint32_t, LldpPortConfig> port_configs_;
    std::map<uint32_t, std::vector<LldpNeighborInfo>> neighbors_by_port_;
    mutable std::mutex lldp_mutex_; // For thread-safe access to shared data

    // Private Helper Methods (implementations will be in lldp_manager.cpp)

    // Builds the LLDP Data Unit (PDU) to be sent.
    // This involves creating Chassis ID, Port ID, TTL, and other optional TLVs.
    std::vector<uint8_t> build_lldpdu(uint32_t port_id, const LldpPortConfig& config);

    // Parses a received LLDPDU.
    // Extracts TLVs and updates neighbor information.
    void parse_lldpdu(const uint8_t* data, size_t len, uint32_t ingress_port);

    // Retrieves the system name (e.g., hostname).
    // Placeholder: Implementation might get this from a ConfigManager or OS API.
    std::string get_system_name() const;

    // Retrieves the system description.
    // Placeholder: Implementation might get this from a ConfigManager or OS API.
    std::string get_system_description() const;

    // Helper to remove expired neighbors
    void expire_neighbors();
};

} // namespace netflow
