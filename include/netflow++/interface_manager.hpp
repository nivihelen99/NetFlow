#ifndef NETFLOW_INTERFACE_MANAGER_HPP
#define NETFLOW_INTERFACE_MANAGER_HPP

#include <cstdint>
#include <vector>
#include <map>
#include <functional> // For std::function
#include <string>     // Potentially for port names in the future
#include <algorithm>  // For std::fill (if needed, though direct initialization is used)

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

    InterfaceManager() = default;

    // Configures a port with the given settings.
    // If the port doesn't exist, it will be created.
    void configure_port(uint32_t port_id, const PortConfig& config) {
        port_configs_[port_id] = config;
        // Ensure stats entry exists if configuring a port for the first time
        if (port_stats_.find(port_id) == port_stats_.end()) {
            port_stats_[port_id] = PortStats(); // Initialize with default (all zero) stats
        }
    }

    // Retrieves the configuration for a given port.
    // Returns std::optional<PortConfig> to handle cases where port might not be configured.
    std::optional<PortConfig> get_port_config(uint32_t port_id) const {
        auto it = port_configs_.find(port_id);
        if (it != port_configs_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    // Retrieves statistics for a given port.
    // Returns default (all zero) stats if the port is not found or has no stats yet.
    PortStats get_port_stats(uint32_t port_id) const {
        auto it = port_stats_.find(port_id);
        if (it != port_stats_.end()) {
            return it->second;
        }
        return PortStats(); // Return default (all zero) stats
    }

    // Clears (resets to zero) statistics for a specific port.
    // If the port doesn't exist, this operation has no effect.
    void clear_port_stats(uint32_t port_id) {
        auto it = port_stats_.find(port_id);
        if (it != port_stats_.end()) {
            it->second = PortStats(); // Reset to default (all zero) stats
        }
        // If port_id not in port_stats_, do nothing (or could create a zeroed entry).
    }

    // Checks if a port is administratively up (enabled).
    // This does not necessarily mean the link is operationally up.
    bool is_port_admin_up(uint32_t port_id) const {
        auto it = port_configs_.find(port_id);
        if (it != port_configs_.end()) {
            return it->second.admin_up;
        }
        return false; // Default to admin down if not configured
    }

    // Placeholder for actual operational link status (would involve hardware interaction)
    // For now, let's assume admin_up implies link_up for simulation if not overridden.
    bool is_port_link_up(uint32_t port_id) const {
        // In a real system, this would query hardware or an internal state maintained by link events.
        // For this placeholder, we can tie it to admin_up or have a separate simulated link state.
        // Let's use a separate map for simulated link states.
        auto it_state = simulated_link_state_.find(port_id);
        if (it_state != simulated_link_state_.end()) {
            return it_state->second;
        }
        // Default to link down if not explicitly simulated up, or could tie to admin_up.
        // Let's default to false if not simulated.
        return false;
    }


    // Registers a callback function to be invoked when a port's link goes up.
    void on_link_up(std::function<void(uint32_t port_id)> callback) {
        if (callback) {
            link_up_callbacks_.push_back(callback);
        }
    }

    // Registers a callback function to be invoked when a port's link goes down.
    void on_link_down(std::function<void(uint32_t port_id)> callback) {
        if (callback) {
            link_down_callbacks_.push_back(callback);
        }
    }

    // Simulates a port's link coming up and invokes registered callbacks.
    void simulate_port_link_up(uint32_t port_id) {
        // Update simulated link state
        simulated_link_state_[port_id] = true;
        // Ensure port config exists, or create a default one if strictly needed for callbacks
        if (port_configs_.find(port_id) == port_configs_.end()) {
            // If callbacks might rely on config, ensure a default one exists
            // configure_port(port_id, PortConfig()); // Or handle as error/warning
        }

        for (const auto& callback : link_up_callbacks_) {
            if (callback) {
                callback(port_id);
            }
        }
    }

    // Simulates a port's link going down and invokes registered callbacks.
    void simulate_port_link_down(uint32_t port_id) {
        // Update simulated link state
        simulated_link_state_[port_id] = false;

        for (const auto& callback : link_down_callbacks_) {
            if (callback) {
                callback(port_id);
            }
        }
    }

    // Helper to update RX stats (example, would be called by data plane)
    void _increment_rx_stats(uint32_t port_id, uint64_t bytes, bool is_error = false, bool is_drop = false) {
        auto it = port_stats_.find(port_id);
        if (it == port_stats_.end()) {
            // Optionally create stats entry if it's missing, or ignore if strict
            port_stats_[port_id] = PortStats(); // Initialize if not present
            it = port_stats_.find(port_id);
        }
        it->second.rx_packets++;
        it->second.rx_bytes += bytes;
        if (is_error) it->second.rx_errors++;
        if (is_drop) it->second.rx_drops++;
    }

    // Helper to update TX stats (example)
    void _increment_tx_stats(uint32_t port_id, uint64_t bytes, bool is_error = false, bool is_drop = false) {
         auto it = port_stats_.find(port_id);
        if (it == port_stats_.end()) {
            port_stats_[port_id] = PortStats();
            it = port_stats_.find(port_id);
        }
        it->second.tx_packets++;
        it->second.tx_bytes += bytes;
        if (is_error) it->second.tx_errors++;
        if (is_drop) it->second.tx_drops++;
    }


private:
    std::map<uint32_t, PortConfig> port_configs_;
    std::map<uint32_t, PortStats> port_stats_;
    std::map<uint32_t, bool> simulated_link_state_; // For is_port_link_up simulation

    std::vector<std::function<void(uint32_t port_id)>> link_up_callbacks_;
    std::vector<std::function<void(uint32_t port_id)>> link_down_callbacks_;
};

} // namespace netflow

#endif // NETFLOW_INTERFACE_MANAGER_HPP
