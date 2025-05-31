#ifndef NETFLOW_INTERFACE_MANAGER_HPP
#define NETFLOW_INTERFACE_MANAGER_HPP

#include <cstdint>
#include <vector>
#include <map>
#include <functional> // For std::function
#include <string>     // Potentially for port names in the future
#include <algorithm>  // For std::fill (if needed, though direct initialization is used)
#include <optional>   // For std::optional

namespace netflow {

class InterfaceManager {
public:
    struct PortStats {
        uint64_t rx_packets = 0;
        uint64_t tx_packets = 0;
        uint64_t rx_bytes = 0;
        uint64_t tx_bytes = 0;
        uint64_t rx_errors = 0;
        uint64_t tx_errors = 0;
        uint64_t rx_drops = 0;
        uint64_t tx_drops = 0;

        PortStats() = default; // All members initialized by default member initializers
    };

    struct PortConfig {
        bool admin_up = false;          // Administrative status (true = enabled, false = disabled)
        uint32_t speed_mbps = 1000;     // Speed in Megabits per second (e.g., 10, 100, 1000, 10000)
        bool full_duplex = true;        // True for full-duplex, false for half-duplex
        bool auto_negotiation = true;   // True if auto-negotiation is enabled
        uint32_t mtu = 1500;            // Maximum Transmission Unit in bytes (excluding L2 header for IP MTU)

        PortConfig() = default; // All members initialized by default member initializers
    };

    InterfaceManager();

    // Configures a port with the given settings.
    // If the port doesn't exist, it will be created.
    void configure_port(uint32_t port_id, const PortConfig& config);

    // Retrieves the configuration for a given port.
    // Returns std::optional<PortConfig> to handle cases where port might not be configured.
    std::optional<PortConfig> get_port_config(uint32_t port_id) const;

    // Retrieves statistics for a given port.
    // Returns default (all zero) stats if the port is not found or has no stats yet.
    PortStats get_port_stats(uint32_t port_id) const;

    // Clears (resets to zero) statistics for a specific port.
    // If the port doesn't exist, this operation has no effect.
    void clear_port_stats(uint32_t port_id);

    // Checks if a port is administratively up (enabled).
    // This does not necessarily mean the link is operationally up.
    bool is_port_admin_up(uint32_t port_id) const;

    // Placeholder for actual operational link status (would involve hardware interaction)
    bool is_port_link_up(uint32_t port_id) const;

    // Registers a callback function to be invoked when a port's link goes up.
    void on_link_up(std::function<void(uint32_t port_id)> callback);

    // Registers a callback function to be invoked when a port's link goes down.
    void on_link_down(std::function<void(uint32_t port_id)> callback);

    // Simulates a port's link coming up and invokes registered callbacks.
    void simulate_port_link_up(uint32_t port_id);

    // Simulates a port's link going down and invokes registered callbacks.
    void simulate_port_link_down(uint32_t port_id);

public: // Changed from protected to public
    // Helper to update RX stats (example, would be called by data plane)
    void _increment_rx_stats(uint32_t port_id, uint64_t bytes, bool is_error = false, bool is_drop = false);

    // Helper to update TX stats (example)
    void _increment_tx_stats(uint32_t port_id, uint64_t bytes, bool is_error = false, bool is_drop = false);

private:
    std::map<uint32_t, PortConfig> port_configs_;
    std::map<uint32_t, PortStats> port_stats_;
    std::map<uint32_t, bool> simulated_link_state_; // For is_port_link_up simulation

    std::vector<std::function<void(uint32_t port_id)>> link_up_callbacks_;
    std::vector<std::function<void(uint32_t port_id)>> link_down_callbacks_;
};

} // namespace netflow

#endif // NETFLOW_INTERFACE_MANAGER_HPP
