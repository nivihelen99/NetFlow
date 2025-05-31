#ifndef NETFLOW_INTERFACE_MANAGER_HPP
#define NETFLOW_INTERFACE_MANAGER_HPP

#include "netflow++/packet.hpp" // For IpAddress and MacAddress
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

    // --- Stubs for ArpProcessor and IcmpProcessor dependencies ---
    std::vector<uint32_t> get_all_interface_ids() const {
        std::vector<uint32_t> ids;
        for(const auto& pair : port_configs_) {
            ids.push_back(pair.first);
        }
        return ids; // Returns configured port IDs, or empty if none
    }

    bool is_ip_local_to_interface(IpAddress ip, uint32_t port_id) const {
        // Placeholder stub: In a real implementation, this would check if 'ip'
        // is configured on the interface associated with 'port_id'.
        // For now, assume no IP is local to any interface to avoid unintended ARP replies.
        (void)ip; (void)port_id; // Suppress unused parameter warnings
        return false;
    }

    std::optional<MacAddress> get_interface_mac(uint32_t port_id) const {
        // Placeholder stub: Real implementation would fetch MAC from interface config.
        // Returning MAC 00:00:00:00:00:00 for now if port is valid.
        // This is a very basic stub and likely not correct for actual operation.
        if (port_configs_.count(port_id)) {
            // This should ideally come from a per-interface MAC address configuration
            // For now, returning a dummy MAC. A proper implementation is needed.
            // static const uint8_t dummy_mac_bytes[] = {0x00,0x00,0x00,0x00,0x00,0x01}; // Example dummy
            // return MacAddress(dummy_mac_bytes);
            return std::nullopt; // Safer to return nullopt if not properly implemented
        }
        (void)port_id;
        return std::nullopt;
    }

    bool is_port_valid(uint32_t port_id) const {
        // Placeholder stub: Checks if port_id is known (configured).
        return port_configs_.count(port_id) > 0;
    }

    std::optional<IpAddress> get_interface_ip(uint32_t port_id) const {
        // Placeholder stub: Real implementation would fetch IP from interface config.
        // For now, returning no IP.
        // This needs to be properly implemented to return the interface's IP address
        // (likely in network byte order).
        (void)port_id;
        return std::nullopt;
    }

    std::vector<uint32_t> get_all_l3_interface_ids() const {
        // Placeholder stub: Assumes all configured interfaces could be L3 capable.
        // A real implementation would distinguish L2/L3 interfaces.
        return get_all_interface_ids();
    }
    // --- End Stubs ---


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
